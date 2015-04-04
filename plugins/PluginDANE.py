#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:         PluginDANE.py
# Purpose:      Tests the target server for DANE support.
#
# Author:       tmaier
#
# Copyright:    2015 SSLyze developers
#
#   SSLyze is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 2 of the License, or
#   (at your option) any later version.
#
#   SSLyze is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with SSLyze.  If not, see <http://www.gnu.org/licenses/>.
#-------------------------------------------------------------------------------

from xml.etree.ElementTree import Element

from plugins import PluginBase
from utils.SSLyzeSSLConnection import create_sslyze_connection, SSLHandshakeRejected
from nassl._nassl import OpenSSLError, WantX509LookupError, WantReadError
from nassl import TLSV1, TLSV1_1, TLSV1_2, SSLV23, SSLV3

import dns.resolver
import base64
import hashlib
from Crypto.Util.asn1 import DerSequence
import dns.name
import dns.query
import dns.dnssec
import dns.message
import dns.resolver
import dns.rdatatype
import dns.rdtypes.IN.A as A
import dns.rdtypes.ANY.CNAME as CNAME
import dns.rdtypes.ANY.RRSIG as RRSIG


class DNSSECException(Exception):
    pass


def get_trust_anchor():
    # Hardcoded root keys
    key_data = [{'owner': '.',
                 'flags': '257',
                 'protocol': '3',
                 'algorithm': '8',
                 'key': 'AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjFFVQ'
                        'UTf6v58fLjwBd0YI0EzrAcQqBGCzh/RStIoO8g0NfnfL2MTJRkxoXbfDaUe'
                        'VPQuYEhg37NZWAJQ9VnMVDxP/VHL496M/QZxkjf5/Efucp2gaDX6RS6CXpo'
                        'Y68LsvPVjR0ZSwzz1apAzvN9dlzEheX7ICJBBtuA6G3LQpzW5hOA2hzCTMj'
                        'JPJ8LbqF6dsV6DoBQzgul0sGIcGOYl7OyQdXfZ57relSQageu+ipAdTTJ25'
                        'AsRTAoub8ONGcLmqrAmRLKBP1dfwhYB4N7knNnulqQxA+Uk1ihz0='},
                {'owner': '.',
                 'flags': '256',
                 'protocol': '3',
                 'algorithm': '8',
                 'key': 'AwEAAe3fSrbLBy3LOS7pnxEUhvPZTE2H5dIGsI/UfruI/nOEvWWa/PSX2BF'
                        'edBkEqOlYdjdNF2f+6lmfk2Od/xu0v5bVqxFE+/24v3hZSlWBxvXzPTAGHr'
                        'bW/IJYEPqlzVOAS4XdUgHg0N7IbLywNHMvB+Yf+Nm6ctyXXFLV4WTNnzs7'}]

    # Generate delegation signer hashes
    ds_records = []
    for key in key_data:
        dnskey_record_text = key['flags'] + ' ' + key['protocol'] + ' ' + key['algorithm'] + ' ' + key['key']
        dnskey_record = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DNSKEY, dnskey_record_text)
        ds_records.append(make_ds('.', dnskey_record, 'SHA1'))
        ds_records.append(make_ds('.', dnskey_record, 'SHA256'))
    return ds_records


def dns_query(domain, nameserver, rr_type, want_dnssec=False):
    request = dns.message.make_query(domain, rr_type, want_dnssec=want_dnssec, use_edns=want_dnssec, payload=4096)
    request.flags |= dns.flags.AD
    #timeout = 0.1  # Only use with caches!
    timeout = 0.2
    attempt = 1
    max_attempts = 5
    while attempt <= max_attempts:
        try:
            return dns.query.udp(request, nameserver, timeout=timeout)
        except dns.exception.DNSException:
            if attempt < max_attempts:
                timeout *= 2
            attempt += 1
    return None


def make_ds(domain, dnskey_record, hash_algorithm):
    ds_record = dns.dnssec.make_ds(dns.name.from_text(domain), dnskey_record, hash_algorithm)
    return ds_record


def get_ds_matching_key(domain, ds_record, dnskey_records):
    ds_hash = ds_record.to_text().split(' ')[3]
    for dnskey_record in dnskey_records:
        if ds_record.digest_type == 1:
            hash_value = make_ds(domain, dnskey_record, 'SHA1').to_text().split(' ')[3]
        elif ds_record.digest_type == 2:
            hash_value = make_ds(domain, dnskey_record, 'SHA256').to_text().split(' ')[3]
        else:
            raise DNSSECException('Digest type not supported')

        if hash_value.upper() == ds_hash.upper():
            return dnskey_record

    return None


def validate(rrset, rrsigset, domain_name, keys):
    try:
        keys = dns.rrset.from_rdata_list(domain_name, 1, keys)
        dns.dnssec.validate(rrset, rrsigset, {domain_name: keys})
    except dns.dnssec.ValidationFailure:
        return False
    else:
        return True


def fix_response_order((records, sig_records)):
    for record in records:
        if str(type(record)) == '<class \'dns.rdtypes.ANY.RRSIG.RRSIG\'>':
            return sig_records, records
    return records, sig_records


def find_ipv4_nameserver(ns_candidates, nameserver, zone):
    for ns_candidate in ns_candidates:
        dns_response = dns_query(ns_candidate.to_text(), nameserver, dns.rdatatype.A)
        if dns_response and len(dns_response.answer) > 0:
            ns_candidate_addr = dns_response.answer[0][0].to_text()
            return ns_candidate, ns_candidate_addr
    return None


def is_record_type_list(records, record_type):
    for record in records:
        if isinstance(record, record_type):
            return True
    return False


def validate_trust_chain(domain_name):
    original_domain = domain_name

    if not domain_name or domain_name == '':
        raise DNSSECException('No domain')

    # Ensure fqdn (fully qualified domain name)
    if original_domain[-1] != '.':
        original_domain += '.'
    # '##### ' + original_domain + ' #####'

    # Initialize validation
    ds_records = get_trust_anchor()
    #default_nameserver = '127.0.1.1'
    default_nameserver = '8.8.8.8'

    domain_parts = list(reversed([domain_part for domain_part in original_domain.split('.')]))
    zone = ''

    # Validate trust chain
    for i, domain_part in enumerate(domain_parts):
        # Construct zone name
        if zone == '':
            zone = '.'
        elif zone == '.':
            zone = domain_part + zone
        else:
            zone = domain_part + '.' + zone

        ##########################################
        # GET NAMESERVER(S)
        ##########################################
        # Get authoritative nameserver
        dns_response = dns_query(zone, default_nameserver, dns.rdatatype.NS)
        if not dns_response or len(dns_response.answer) == 0:
            # zone, '\tCannot find nameserver for zone'
            return False
        ns_candidates = dns_response.answer[0]
        nameserver_data = find_ipv4_nameserver(ns_candidates, default_nameserver, zone)
        if not nameserver_data:
            # zone, '\tCannot find valid nameserver IP (IPv4) for zone'
            return False
        (nameserver, nameserver_addr) = nameserver_data

        ##########################################
        # GET/VALIDATE DNSKEY RR(S)
        ##########################################
        # Get DNSKEY records for zone
        dns_response = dns_query(zone, nameserver_addr, dns.rdatatype.DNSKEY, want_dnssec=True)
        if not dns_response:
            pass#print zone, '\tTried to get DNSKEY rr(s). DNS server is not available'
        elif len(dns_response.answer) != 2:
            pass#print zone, '\tCannot get DNSKEY rr(s) for domain'
        else:
            (dnskey_records, dnskey_sig_records) = fix_response_order(dns_response.answer)
            #print zone, '\tGot', len(dnskey_records), 'DNSKEY rr(s) with', len(dnskey_sig_records), 'signature rr(s)'

            # Validate DNSKEY rr(s) with DS rr(s)
            validated_keys = []
            if len(ds_records) > 0:
                for ds_record in ds_records:
                    validated_key = get_ds_matching_key(zone, ds_record, dnskey_records)
                    if validated_key and validated_key not in validated_keys:
                        validated_keys.append(validated_key)
                #print zone, '\tGot', len(validated_keys), 'matching DNSKEY rr(s) for parent DS rr(s)'
            else:
                #print zone, '\tNo DS records available for validation.'
                validated_keys += dnskey_records

            # Validate DNSKEY rr(s) with signatur rr(s)
            if len(validated_keys) > 0:
                if validate(dnskey_records, dnskey_sig_records, dns.name.from_text(zone), validated_keys):
                    #print zone, '\tValidated one signature rr for DNSKEY rr set'
                    validated_keys = list(validated_keys)
                    for validated_key in dnskey_records:
                        if validated_key not in validated_keys:
                            validated_keys.append(validated_key)
                else:
                    pass#print zone, '\tNone of the signature rr(s) for the DNSKEY rr set could be validated'

        ##########################################
        # GET/VALIDATE A RR(S)
        ##########################################
        # Get A records for original domain
        dns_response = dns_query(original_domain, nameserver_addr, dns.rdatatype.A, want_dnssec=True)
        if not dns_response:
            #print zone, '\tTried to get A records. DNS server', nameserver, 'is not available'
            return False
        if len(dns_response.answer) == 2:
            (a_records, a_sig_records) = fix_response_order(dns_response.answer)

            if is_record_type_list(a_records, CNAME.CNAME) and is_record_type_list(a_sig_records, A.A):
                # CNAME case
                cname_records = a_records
                a_records = a_sig_records
                #print zone, '\tGot', len(cname_records), 'CNAME rr(s) for', original_domain
                #print zone, '\tGot', len(a_records), 'A rr(s) for', original_domain
                #print zone, '\tCannot find signature rr(s) for A rr set for', original_domain
            elif is_record_type_list(a_records, A.A) and is_record_type_list(a_sig_records, RRSIG.RRSIG):
                #print zone, '\tGot', len(a_records), 'A rr(s) with', len(a_sig_records), 'signature rr(s) for', \
                #    original_domain

                # Validate A rr(s) with signatur rr(s)
                if validate(a_records, a_sig_records, dns.name.from_text(zone), validated_keys):
                    #print zone, '\tValidated one signature rr for A rr set for', original_domain
                    return True
                else:
                    #print zone, '\tSignature validation for A rr(s) failed for', original_domain
                    return False

        elif len(dns_response.answer) == 4:
            (cname_records, cname_sig_records, a_records, a_sig_records) = dns_response.answer
            #print zone, '\tGot', len(cname_records), 'CNAME rr(s) with', len(cname_sig_records), \
            #    'signature rr(s) for', original_domain

            # Validate CNAME rr(s) with signatur rr(s)
            if validate(cname_records, cname_sig_records, dns.name.from_text(zone), validated_keys):
                pass#print zone, '\tValidated one signature rr for CNAME rr set for', original_domain
            else:
                pass#print zone, '\tSignature validation for CNAME rr(s) failed for', original_domain

            #print zone, '\tGot', len(a_records), 'A rr(s) with', len(a_sig_records), 'signature rr(s) for', \
            #    original_domain

            # Validate A rr(s) with signatur rr(s)
            if validate(a_records, a_sig_records, dns.name.from_text(zone), validated_keys):
                #print zone, '\tValidated one signature rr for A rr set for', original_domain
                return True
            else:
                #print zone, '\tSignature validation for A rr(s) failed for', original_domain
                return False

        elif len(dns_response.answer) == 1:
            #print zone, '\tGot', len(dns_response.answer[0]), 'A rr(s) for', original_domain
            #print zone, '\tCannot find signature rr(s) for A rr set for', original_domain
            return False
        else:
            if zone != original_domain:
                ##########################################
                # GET NEXT DS RR(S)
                ##########################################
                # Build next zone
                if zone == '.':
                    next_zone = domain_parts[i+1] + zone
                else:
                    next_zone = domain_parts[i+1] + '.' + zone

                # Get DS records
                dns_response = dns_query(next_zone, nameserver_addr, dns.rdatatype.DS, want_dnssec=True)
                if not dns_response:
                    pass#print zone, '\tTried to get DS. DNS server', nameserver, 'is not available'
                elif len(dns_response.answer) == 2:
                    (ds_records, ds_sig_records) = fix_response_order(dns_response.answer)
                    #print zone, '\tGot', len(ds_records), 'DS rr(s) for', next_zone
                    # Validate DS rr(s) with signatur rr(s)
                    if validate(ds_records, ds_sig_records, dns.name.from_text(zone), validated_keys):
                        pass#print zone, '\tValidated one signature rr for DS rr set for', next_zone
                else:
                    #print zone, '\tNo DS rr(s) found for', next_zone
                    ds_records = []
            else:
                pass#print zone, '\tCannot find A rr(s) for', original_domain


class PluginDANE(PluginBase.PluginBase):

    interface = PluginBase.PluginInterface("PluginDANE",  "")
    interface.add_command(command="dane", help="Tests the server(s) on DANE support and validates data (experimental).")

    def process_task(self, target, command, args):
        cmdTitle = 'DANE'

        # TODO Support xml output
        xmlOutput = Element(command, title=cmdTitle)
        #xmlOutput.append(Element('dane', isVulnerable='True'))

        db_output = {}

        txtOutput = [self.PLUGIN_TITLE_FORMAT(cmdTitle)]

        try:
            (target_domain, _, target_port, _) = target
            import socket
            target_domain = socket.gethostbyaddr(target_domain)[0]
            tlsa_domain = '_' + str(target_port) + '._tcp.' + target_domain + '.'

            # Get TLSA records
            answers = dns.resolver.query(tlsa_domain, 'TLSA')

            # DANE support?
            if len(answers) > 0:
                txtOutput.append(self.FIELD_FORMAT('DANE support', 'Yes'))
                db_output['isSupported'] = True

                successful_validations = []

                # Retrieve certificate
                cert = self._get_cert(target, None)[0][0]
                tls_cert = cert.as_pem()
                tls_cert = tls_cert.replace('-----BEGIN CERTIFICATE-----', '').replace('-----END CERTIFICATE-----', '')
                tls_cert = base64.decodestring(tls_cert)

                for answer in answers:
                    tlsa_record = str(answer).split(' ')

                    # Certificate usage
                    #   0 ->
                    #   1 ->
                    #   2 ->
                    #   3 -> DANE-EE (Domain-issued certificate)

                    # Selector
                    #   0 -> Full certificate
                    #   1 -> SubjectPublicKeyInfo (public key only)

                    # Matching type
                    #   0 -> Full match, 1 -> SHA-256 hash, 2 -> SHA-512 hash

                    (cert_usage, selector, matching_type, tlsa_data) = (tlsa_record[0], int(tlsa_record[1]), int(tlsa_record[2]), tlsa_record[3])

                    # Build hash
                    plain = tls_cert
                    if selector == 1:  # Exception for SubjectPublicKeyInfo
                        # Extract public key
                        derseq = DerSequence()
                        derseq.decode(plain)
                        tbsCertificate = DerSequence()
                        tbsCertificate.decode(derseq[0])
                        plain = tbsCertificate[6]

                    matching_types = ['', 'sha256', 'sha512']
                    hash = hashlib.new(matching_types[matching_type])  # TODO Should depend on matching type
                    hash.update(plain)
                    tls_cert_hash = hash.hexdigest()

                    if tls_cert_hash == tlsa_data:
                        successful_validations.append(tlsa_data)

                if len(successful_validations) > 0:
                    txtOutput.append(self.FIELD_FORMAT('DANE validation', 'Successful'))
                    db_output['validated'] = True
                    for i, cert in enumerate(successful_validations):
                        txtOutput.append(self.FIELD_FORMAT('Match ' + str(i+1), cert))

                    try:
                        dnssec_validated = validate_trust_chain(target_domain)
                    except Exception:
                        dnssec_validated = False
                    db_output['dnssecValidated'] = dnssec_validated

                    if dnssec_validated:
                        txtOutput.append(self.FIELD_FORMAT('DNSSEC validation', 'Successful'))
                    else:
                        txtOutput.append(self.FIELD_FORMAT('DNSSEC validation', 'Failed'))
                else:
                    txtOutput.append(self.FIELD_FORMAT('DANE validation', 'Failed'))
                    db_output['validated'] = False
            else:
                txtOutput.append(self.FIELD_FORMAT('DANE support', 'no'))
                db_output['isSupported'] = False
        except dns.resolver.NoAnswer:
            txtOutput.append(self.FIELD_FORMAT('DANE support', 'no'))
            db_output['isSupported'] = False
        except dns.resolver.NXDOMAIN:
            txtOutput.append(self.FIELD_FORMAT('DANE support', 'no'))
            db_output['isSupported'] = False

        return PluginBase.PluginResult(txtOutput, xmlOutput, db_output)


    def _get_cert(self, target, storePath):
        """
        Connects to the target server and uses the supplied trust store to
        validate the server's certificate. Returns the server's certificate and
        OCSP response.
        """
        (_, _, _, sslVersion) = target
        sslConn = create_sslyze_connection(target, self._shared_settings,
                                           sslVersion,
                                           sslVerifyLocations=storePath)

        # Enable OCSP stapling
        sslConn.set_tlsext_status_ocsp()

        try:  # Perform the SSL handshake
            sslConn.connect()

            ocspResp = sslConn.get_tlsext_status_ocsp_resp()
            x509Chain = sslConn.get_peer_cert_chain()
            (_, verifyStr) = sslConn.get_certificate_chain_verify_result()

        except ClientCertificateRequested:  # The server asked for a client cert
            # We can get the server cert anyway
            ocspResp = sslConn.get_tlsext_status_ocsp_resp()
            x509Chain = sslConn.get_peer_cert_chain()
            (_, verifyStr) = sslConn.get_certificate_chain_verify_result()

        finally:
            sslConn.close()

        return (x509Chain, verifyStr, ocspResp)
