# Copyright (c) 2014 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import unittest

from oss2swift import etree


class TestOss2swiftEtree(unittest.TestCase):
    def test_xml_namespace(self):
        def test_xml(ns, prefix):
            return '<A %(ns)s><%(prefix)sB>C</%(prefix)sB></A>' % \
                ({'ns': ns, 'prefix': prefix})

        # No namespace is same as having the oss namespace.
        xml = test_xml('', '')
        elem = etree.fromstring(xml)
        self.assertEqual(elem.find('./B').text, 'C')

        # The oss namespace is handled as no namespace.
        xml = test_xml('xmlns="%s"' % etree.XMLNS_OSS, '')
        elem = etree.fromstring(xml)
        self.assertEqual(elem.find('./B').text, 'C')

        xml = test_xml('xmlns:oss="%s"' % etree.XMLNS_OSS, 'oss:')
        elem = etree.fromstring(xml)
        self.assertEqual(elem.find('./B').text, 'C')

        # Any namespaces without a prefix work as no namespace.
        xml = test_xml('xmlns="http://example.com/"', '')
        elem = etree.fromstring(xml)
        self.assertEqual(elem.find('./B').text, 'C')

        xml = test_xml('xmlns:oss="http://example.com/"', 'oss:')
        elem = etree.fromstring(xml)
        self.assertEqual(elem.find('./B'), None)

    def test_xml_with_comments(self):
        xml = '<A><!-- comment --><B>C</B></A>'
        elem = etree.fromstring(xml)
        self.assertEqual(elem.find('./B').text, 'C')

    def test_tostring_with_nonascii_text(self):
        elem = etree.Element('Test')
        sub = etree.SubElement(elem, 'FOO')
        sub.text = '\xef\xbc\xa1'
        self.assertTrue(isinstance(sub.text, str))
        xml_string = etree.tostring(elem)
        self.assertTrue(isinstance(xml_string, str))

    def test_fromstring_with_nonascii_text(self):
        input_str = '<?xml version="1.0" encoding="UTF-8"?>\n' \
                    '<Test><FOO>\xef\xbc\xa1</FOO></Test>'
        elem = etree.fromstring(input_str)
        text = elem.find('FOO').text
        self.assertEqual(text, '\xef\xbc\xa1')
        self.assertTrue(isinstance(text, str))


if __name__ == '__main__':
    unittest.main()
