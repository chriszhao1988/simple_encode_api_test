/**
 * Create with 加解密实验
 * Author: ChrisChiu
 * Date: 2023/11/14
 * Desc
 */
const nodeRSA = require('node-rsa');
const fs = require('fs');

const PUBLICKEY = fs.readFileSync('./servers_public_key.pem', 'utf8');
const PRIVATEKEY = fs.readFileSync('./servers_private_key.pem', 'utf8');
/*const key = new nodeRSA();
key.importKey(PUBLICKEY,'pkcs8-public-pem');
key.importKey(PRIVATEKEY,'pkcs8-private-pem');
const key2 = new nodeRSA();
key2.importKey(PUBLICKEY,'pkcs8-public-pem');
key2.importKey(PRIVATEKEY,'pkcs8-private-pem');*/
const sender_key = {
    publicKey : new nodeRSA(PUBLICKEY),
    privateKey : new nodeRSA(PRIVATEKEY)
}
const reciver_key = {
    publicKey : new nodeRSA(PUBLICKEY),
    privateKey : new nodeRSA(PRIVATEKEY)
}



/* RSA接口签名+加密方式 */
/* timestamp + nonce 防止重放攻击 */
/* signed 使用发送方的私钥进行签名验证 低配版也可以算hash */
/* 整体使用接收方的公钥加密  */
/* 请求数据序列化保障待签数据的一致性 */


const testRequestObj = {
    name: 'Ishihara Satomi',
    a: 100,
    b: 200
};

/* sender */
const sendRequest = () => {
    const newobj = {};
    /* 参数序列化 */
    Object.keys(testRequestObj).sort().forEach(key => newobj[key] = testRequestObj[key]);
    const timestamp = new Date().getTime();
    const rand_num = Math.floor(Math.random() * 1000000);
    /* 签名newobj */
    const signed = sender_key.privateKey.sign(JSON.stringify(newobj), 'hex','utf8');
    const reqObj = {
        obj: testRequestObj, signed, timestamp, nonce: rand_num
    }
    console.dir(reqObj);
    /* 用公钥加密数据 */
    const nobj = reciver_key.publicKey.encrypt(JSON.stringify(reqObj),'base64');
    console.dir(nobj);
    return nobj;
}

/* receiver */
const receiveRequest = (hex) => {
    /* 检查nonce是否已经被请求（一般存在redis） */
    /* 检查timestamp是否在有效范围 （比如60s）*/
    /* 私钥解密 */
    const request = reciver_key.privateKey.decrypt(hex,'json');
    const newobj = {}
    /* 参数序列化 */
    Object.keys(request.obj).sort().forEach(key => newobj[key] = testRequestObj[key]);
    /* 验证签名 */
    const verified = sender_key.publicKey.verify(Buffer.from(JSON.stringify(newobj)), request.signed,'utf8','hex');
    console.dir(verified);

}

const hex = sendRequest();
receiveRequest(hex);

