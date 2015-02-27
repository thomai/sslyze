#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:         PluginCompression.py
# Purpose:      Tests the server for Zlib compression support.
#
# Author:       tritter, alban
#
# Copyright:    2012 SSLyze developers
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

from utils.SSLyzeSSLConnection import create_sslyze_connection
from nassl.SslClient import ClientCertificateRequested


class PluginCompression(PluginBase.PluginBase):

    interface = PluginBase.PluginInterface(title="PluginCompression", description="")
    interface.add_command(
        command="compression",
        help="Tests the server(s) for Zlib compression support.")


    def process_task(self, target, command, args):

        sslConn = create_sslyze_connection(target, self._shared_settings)

        # Make sure OpenSSL was built with support for compression to avoid false negatives
        if 'zlib compression' not in sslConn.get_available_compression_methods():
            raise RuntimeError('OpenSSL was not built with support for zlib / compression. Did you build nassl yourself ?')

        try: # Perform the SSL handshake
            sslConn.connect()
            compName = sslConn.get_current_compression_method()
        except ClientCertificateRequested: # The server asked for a client cert
            compName = sslConn.get_current_compression_method()
        finally:
            sslConn.close()

        # Text output
        if compName:
            compTxt = 'VULNERABLE - Server supports Deflate compression'
        else:
            compTxt = 'OK - Compression disabled'

        cmdTitle = 'Deflate Compression'
        txtOutput = [self.PLUGIN_TITLE_FORMAT(cmdTitle)]
        txtOutput.append(self.FIELD_FORMAT(compTxt, ""))

        # XML and DB output
        if compName:
            comp_is_supported = True
        else:
            comp_is_supported = False

        xmlOutput = Element(command, title=cmdTitle)
        xmlNode = Element('compressionMethod', type="DEFLATE", isSupported=str(comp_is_supported))
        xmlOutput.append(xmlNode)

        db_output = {'isSupported': comp_is_supported}

        return PluginBase.PluginResult(txtOutput, xmlOutput, db_output)

