import re
from config import SigProxyConfig as cfg


def get_seclay_request(sig_type: str, sig_data: bytes, sigPosition: str = None) -> bytes:
    ''' return a <CreateXMLSignatureRequest> for requesting either enveloping or
        enveloped XMLDsig from the SecurityLayer signature service.
        sigPosition is the XPath for the element under which an
        enveoped signature shall be positioned, e.g. <md:/EntitiyDescriptor>.
    '''

    def remove_xml_declaration(xml: bytes) -> bytes:
        return re.sub(r'<\?xml[^?]*\?>'.encode('ascii'), '', xml)

    if sig_type == cfg.SIGTYPE_ENVELOPING:
        template = b'''\
<?xml version="1.0" encoding="UTF-8"?>
<sl:CreateXMLSignatureRequest
  xmlns:sl="http://www.buergerkarte.at/namespaces/securitylayer/1.2#">
  <sl:KeyboxIdentifier>SecureSignatureKeypair</sl:KeyboxIdentifier>
  <sl:DataObjectInfo Structure="enveloping">
    <sl:DataObject>
      <sl:XMLContent>%s</sl:XMLContent>
    </sl:DataObject>
    <sl:TransformsInfo>
      <sl:FinalDataMetaInfo>
        <sl:MimeType>text/plain</sl:MimeType>
      </sl:FinalDataMetaInfo>
    </sl:TransformsInfo>
  </sl:DataObjectInfo>
</sl:CreateXMLSignatureRequest> '''
        sigdata_nodecl = remove_xml_declaration(sig_data)
        return template % sigdata_nodecl

    if sig_type == cfg.SIGTYPE_ENVELOPED:
        template = b'''\
<?xml version="1.0" encoding="UTF-8"?>
<sl:CreateXMLSignatureRequest
  xmlns:sl="http://www.buergerkarte.at/namespaces/securitylayer/1.2#">
  <sl:KeyboxIdentifier>SecureSignatureKeypair</sl:KeyboxIdentifier>
  <sl:DataObjectInfo Structure="detached">
    <sl:DataObject Reference=""></sl:DataObject>
    <sl:TransformsInfo>
    <dsig:Transforms xmlns:dsig="http://www.w3.org/2000/09/xmldsig#">
        <dsig:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
      </dsig:Transforms>
      <sl:FinalDataMetaInfo>
        <sl:MimeType>application/xml</sl:MimeType>
      </sl:FinalDataMetaInfo>
    </sl:TransformsInfo>
  </sl:DataObjectInfo>
  <sl:SignatureInfo>
    <sl:SignatureEnvironment>
      <sl:XMLContent>
%s
      </sl:XMLContent>
    </sl:SignatureEnvironment>
    <sl:SignatureLocation xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" Index="0">%s</sl:SignatureLocation>
  </sl:SignatureInfo>
</sl:CreateXMLSignatureRequest> '''
        sigdata_nodecl = remove_xml_declaration(sig_data)
        return template % (sigdata_nodecl, sigPosition.encode('ascii'))
