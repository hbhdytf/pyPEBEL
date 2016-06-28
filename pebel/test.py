__author__ = 'yangtengfei'
from lxml import etree
import xml.etree.cElementTree as ET
from charm.schemes.ibenc.ibenc_sw05 import *
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.toolbox.IBEnc import IBEnc
from charm.toolbox.secretshare import SecretShare


def get_path(c, cTree):
    path = []
    root = cTree.getroot()
    node=root.find(".//class[@attr='%s']" % c)
    if node is None:  # no attributes c or find too many c
        return False
    while node.tag!=root.tag :
        path.insert(0, node.attrib['attr'])
        node = node.getparent()

    return path


tree = etree.parse("classes.xml")
root = tree.getroot()
# root = etree.XML('<root><a><b/></a></root>')
print(etree.tostring(root, encoding='iso-8859-1'))
print(etree.tostring(root, pretty_print=True).decode())
tree = etree.ElementTree(root)
print(tree.getelementpath(root[0][0]))
list(root)

a = root.findall(".//class[@attr='1994']")
print(a[0].getparent().getparent().tag)

path = get_path('qingtian',tree)
print(range(len(path)))
print(path)


group = PairingGroup('SS512')
max_attributes = 6
required_overlap = 4
ibe = IBE_SW05_LUC(group)
(master_public_key, master_key) = ibe.setup(max_attributes, required_overlap)
private_identity = ['insurance', 'id=2345', 'oncology', 'doctor', 'nurse', 'JHU'] #private identity
public_identity = ['insurance', 'id=2345', 'doctor', 'oncology', 'JHU', 'billing', 'misc'] #public identity for encrypt
(pub_ID_hashed, secret_key) = ibe.extract(master_key, private_identity, master_public_key, required_overlap, max_attributes)
print(secret_key)
msg = group.random(GT)
cipher_text = ibe.encrypt(master_public_key, public_identity, msg, max_attributes)
decrypted_msg = ibe.decrypt(master_public_key, secret_key, cipher_text, pub_ID_hashed, required_overlap)
msg == decrypted_msg
