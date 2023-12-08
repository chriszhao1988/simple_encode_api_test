/**
 * Create with 加解密实验
 * Author: ChrisChiu
 * Date: 2023/12/6
 * Desc
 */

const crypto = require('crypto');
const eccrypto = require('eccrypto');

const PRIVATEKEY1 = 'c7357c3bbb59ca58154f29854e980907938854f96b9e7ec797a7823e0f156070';
const PUBLICKEY1 = '04454e9f64cb715bf4687306175f59804bc94b44bfa0e9ee585aeb29e83f87baf4089048c948a487930df670cdf2a048130883dda83f52ee6e6fc7fa0710f6af81';
const PRIVATEKEY2 = '67547e1fc12a2d8725479d55302f5bf0b14fdfacc907edccd990e65c0f99f47b';
const PUBLICKEY2 = '046824a372199293c063df8da1a7f4891e42949adbac249b8b36639b04212271242953d6bd0c73884a2612da3af77314659180ae4cfbdae9891551577475d4a802';

const privatekey1 = Buffer.from(PRIVATEKEY1, 'hex')
const privatekey2 = Buffer.from(PRIVATEKEY2, 'hex')
const publickey1 = Buffer.from(PUBLICKEY1, 'hex')
const publickey2 = Buffer.from(PUBLICKEY2, 'hex')

const signature = async () => {
    /* ECDSA */
    const str = "message to sign";
    const msg = crypto.createHash("sha256").update(str).digest();
    try {
        const signature = await eccrypto.sign(privatekey1, msg);
        const signatureStr = signature.toString('hex');
        const sig = Buffer.from(signatureStr, 'hex');
        const verified = await eccrypto.verify(publickey1, msg, sig);
        console.log("Signature is OK");
    } catch (e) {
        console.log("Signature is BAD");
    }
}


const encryption = async (SECRET) => {
    /* 我们假设加密一方持有privatekey1 */
    const sharkey = await eccrypto.derive(privatekey1, publickey2);
    const key = sharkey.toString('hex');
    const nonce = key.slice(0, 32);
    const cipher = crypto.createCipheriv('chacha20', Buffer.from(key, 'hex'), Buffer.from(nonce, 'hex'));
    let str = cipher.update(SECRET, 'utf8', 'hex');
    str += cipher.final('hex');
    console.dir(str);
    return str;

}

const decryption = async (str) => {
    /* 我们假设解密的一方持有privatekey2 */
    const sharkey = await eccrypto.derive(privatekey2, publickey1);
    const key = sharkey.toString('hex');
    const nonce = key.slice(0, 32);
    const cipher = crypto.createCipheriv('chacha20', Buffer.from(key, 'hex'), Buffer.from(nonce, 'hex'));
    let res = cipher.update(str, 'hex', 'utf8');
    res += cipher.final('utf8');
    console.dir(res);
    return res;
}

const encryptiontest = async () => {
    /* ECDH */
    const SECRET = "secret text";
    const str = await encryption(SECRET);
    const res = await decryption(str);
    if (res === SECRET) {
        console.dir('encryption test is complete.');
    }
}

const encryptiontest2 = async () => {
    /* 这里模拟的场景是通过key1的公钥来加密信息 */
    /* ECIES */
    const SECRET = 'secret text';
    const str = await eccrypto.encrypt(publickey1,Buffer.from(SECRET));
    const res = await eccrypto.decrypt(privatekey1,str);
    if (res.toString() === SECRET) {
        console.dir('encryption test 2 is complete.');
    }

}


signature();
encryptiontest();
encryptiontest2();
