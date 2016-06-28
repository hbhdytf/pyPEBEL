'''
CGAC


* type:            ciphertext-policy attribute-based encryption (public key)
* setting:        Pairing

:Authors:         YTF
:Date:            06/2016
'''

from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEnc import ABEnc
from charm.toolbox.IBEnc import *
from charm.toolbox.IBEnc import IBEnc
from charm.toolbox.secretshare import SecretShare
from lxml import etree

debug = False


class CPabeCGAC(ABEnc):
    """
    '>>> from charm.toolbox.pairinggroup import PairingGroup,GT
    '>>> group = PairingGroup('SS512')
    '>>> cpabe = CPabe09(group)
    '>>> msg = group.random(GT)
    '>>> (master_secret_key, master_public_key) = cpabe.setup()
    '>>> policy = '((ONE or THREE) and (TWO or FOUR))'
    '>>> attr_list = ['THREE', 'ONE', 'TWO']
    '>>> secret_key = cpabe.keygen(master_public_key, master_secret_key, attr_list)
    '>>> cipher_text = cpabe.encrypt(master_public_key, msg, policy)
    '>>> decrypted_msg = cpabe.decrypt(master_public_key, secret_key, cipher_text)
    '>>> decrypted_msg == msg
    True
    """

    def __init__(self, groupObj):
        IBEnc.__init__(self)
        global group, H, util
        group = groupObj
        H = lambda x: group.hash(('0', x), ZR)
        util = SecretShare(group, False)
        global v

    def setup(self, n, d):
        '''
        :Parameters:
           - ``n``: the maximum number of attributes in the system.
                    OR the maximum length of an identity
           - ``d``: the maximum number of depth in the system.
                    OR the maximum length of an identity
           - ``t``: the set overlap required to decrypt
        '''
        g = group.random(G1)
        alpha = group.random(ZR)  # alpha

        g1 = g ** alpha  # G1
        g2 = group.random(G1)  # G2
        uu = [group.random(G1) for x in range(2 * n + 2)]
        u = [group.random(G1) for x in range(d + 1)]
        u[0] = 1
        e = pair(g1, g2)

        # k = g1 ** alpha
        pk = {'g': g, 'g1': g1, 'g2': g2, 'e': e, 'uu': uu, 'u': u}
        mk = {'alpha': alpha}  # master secret

        # default attributes v : n-1
        global v
        v = [str(x) for x in range(n)]
        dv = {'v': v}

        if debug:
            print(pk)
            print(mk)
            print(dv)

        return (pk, mk, dv)

    def get_path(self, c, cTree):
        path = []
        root = cTree.getroot()
        node = root.find(".//class[@attr='%s']" % c)
        if node is None:  # no attributes c or find too many c
            return False
        while node.tag != root.tag:
            path.insert(0, node.attrib['attr'])
            node = node.getparent()

        return path

    def extract(self, mk, Ls, pk, cTree, n):
        cTree = etree.parse("classes.xml")
        global v
        w_hash = [H(x) for x in Ls]  # assumes Ls is a list
        v_hash = [H(x) for x in v]
        c_hash = w_hash + v_hash

        # a n-1 degree polynomial q is generated such that q(0) = alpha
        q = [group.random(ZR) for x in range(n)]
        q[0] = mk['alpha']

        # use secret sharing as building block
        shares = util.genShares(mk['alpha'], n - 1, n, q, c_hash)

        uu = pk['uu']
        u = pk['u']

        l = len(u)-1
        sk = {}
        a, b, d, e = {}, {}, {}, {}

        for i in c_hash:
            j = c_hash.index(i)
            temp = 1
            if j < 0:
                return False
            elif j < len(Ls):
                path = self.get_path(Ls[j], cTree)
                for x in range(1, len(path)):
                    temp = temp * (u[x] ** H(path[x]))
            elif j < len(Ls) + n - 1:
                temp = 1
            r = group.random(ZR)
            a[i] = (pk['g2'] ** shares[j][1]) * ((uu[0] * uu[j] * temp) ** r)
            b[i] = pk['g'] ** r
            d[i] = []
            e[i] = []
            for x in uu:
                d[i].append(x ** r)
            d[i][j] = 1
            for x in range(len(path), l + 1):
                e[i].append(u[x] ** r)

        return (w_hash, {'a': a, 'b': b, 'd': d, 'e': e})
    def encrypt(self, pk, w_prime, M, n):
        '''
        Encryption with the public key, Wprime and the message M in G2
        '''
        w_prime_hash = [H(x) for x in w_prime]
        s = group.random(ZR)

        Eprime = M * (pair(pk['g1'], pk['g2']) ** s)
        Eprimeprime = pk['g'] ** s

        E = {}
        for i in w_prime_hash:
            E[i] = self.eval_T(pk, n, i) ** s

        return { 'wPrime':w_prime_hash, 'Eprime':Eprime, 'Eprimeprime':Eprimeprime,'E':E}

def main():
    group = PairingGroup('SS512')
    cgac = CPabeCGAC(group)
    max_attributes = 6
    max_depth = 5
    required_overlap = 4
    (master_public_key, master_key, default_attributes) = cgac.setup(max_attributes, max_depth)
    Ls=['Yehuimei','audio']
    (hash_ID,sk)=cgac.extract(master_key, Ls, master_public_key, cTree = None, n=max_attributes)
    print(sk)

if __name__ == "__main__":
    debug = True
    main()
