/**
 * Create with 加解密实验
 * Author: ChrisChiu
 * Date: 2023/12/20
 * Desc
 */
const crypto = require('crypto');
const eccrypto = require('eccrypto');
const fs = require('fs');

const PRIVATEKEY1 = 'c7357c3bbb59ca58154f29854e980907938854f96b9e7ec797a7823e0f156070';
const PUBLICKEY1 = '04454e9f64cb715bf4687306175f59804bc94b44bfa0e9ee585aeb29e83f87baf4089048c948a487930df670cdf2a048130883dda83f52ee6e6fc7fa0710f6af81';
const PRIVATEKEY2 = '67547e1fc12a2d8725479d55302f5bf0b14fdfacc907edccd990e65c0f99f47b';
const PUBLICKEY2 = '046824a372199293c063df8da1a7f4891e42949adbac249b8b36639b04212271242953d6bd0c73884a2612da3af77314659180ae4cfbdae9891551577475d4a802';

const privatekey1 = Buffer.from(PRIVATEKEY1, 'hex')
const privatekey2 = Buffer.from(PRIVATEKEY2, 'hex')
const publickey1 = Buffer.from(PUBLICKEY1, 'hex')
const publickey2 = Buffer.from(PUBLICKEY2, 'hex')

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
    let res = cipher.update(str, 'hex');
    res += cipher.final();
    console.dir(res);
    return res;
}

const encryptiontest = async () => {
    /* ECIES */
    const start = new Date().getTime();
    /* 读取源文件 */
    const r = await fs.readFileSync('file.shp');
    /* 对源文件使用接收方公钥加密 */
    let enContent = await eccrypto.encrypt(publickey1,r);
    /* 结果转字符串 */
    enContent = JSON.stringify(enContent);
    /* 融合密钥ECDH加密 */
    enContent = await encryption(enContent);
    /* 写入 形成待发送的加密文件 */
    await fs.writeFileSync('file1.txt',enContent);
    const end = new Date().getTime();

    const start2 = new Date().getTime();
    /* 读取 接收到的加密文件 */
    let r2 = await fs.readFileSync('file1.txt',{encoding:'utf8'});
    /* 融合密钥ECDH解密 */
    r2 = await decryption(r2);
    /* 字符串转对象 */
    r2 = JSON.parse(r2);
    /* 遍历内容恢复Buffer */
    for(i in r2){
        r2[i] = Buffer.from(r2[i].data);
    }
    /* 接收方私钥解密内容 */
    const res = await eccrypto.decrypt(privatekey1,r2);
    /* 写入文件恢复为源文件 */
    await fs.writeFileSync('file2.shp',res);
    const end2 = new Date().getTime();

    console.dir(`加密发送过程耗时${end-start}ms,解密接收过程耗时${end2-start2}ms`);
}

encryptiontest();
