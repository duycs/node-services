import * as crypto from "crypto";

const generateKeys = (length: number) => {
    const data = crypto.generateKeyPairSync("rsa", {
        modulusLength: length ?? 2048,
        publicKeyEncoding: {
          type: "pkcs1",
          format: "pem",
        },
        privateKeyEncoding: {
          type: "pkcs1",
          format: "pem",
        },
    });

	return data;
}

const encryptedData = (data: any, publicKey: string) => crypto.publicEncrypt(
	{
		key: publicKey,
		padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
		oaepHash: "sha256",
	},
	// We convert the data string to a buffer using `Buffer.from`
	Buffer.from(data, 'base64')
)

const decryptedData = (encryptedData: any, privateKey: string) =>  crypto.privateDecrypt(
	{
		key: privateKey,
		// In order to decrypt the data, we need to specify the
		// same hashing function and padding scheme that we used to
		// encrypt the data in the previous step
		padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
		oaepHash: "sha256",
	},
	encryptedData
)

const signature = (verifiableData: any, privateKey: string) => crypto.sign(
	"sha256", 
	Buffer.from(verifiableData), {
	key: privateKey,
	padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
})

const isVerified = (verifiableData: any, signature: any, publicKey: string) => crypto.verify(
	"sha256",
	Buffer.from(verifiableData),
	{
		key: publicKey,
		padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
	},
	signature
)

export const toBase64 = (data: string) => {
	return Buffer.from(data).toString('base64');
}

export const toString = (data: string) => {
	return Buffer.from(data, 'base64').toString('utf-8');
}

export const encrypt  = (data : string, publicKey: string) => {
    return encryptedData(data, publicKey).toString("base64");
}

export const decrypt  = (data : string, privateKey: string) => {
    return decryptedData(Buffer.from(data, "base64"), privateKey).toString("base64");
}

export const sign  = (data : string, privateKey: string) => {
    return signature(data, privateKey).toString("base64");
}

export const verify  = (data : string, signature : string, publicKey: string) => {
	try{
    	return isVerified(data, Buffer.from(signature, "base64"), publicKey);
	}catch(error){
		throw new Error(error);
	}
}

export const genKeys = (length: number = 2048) => {
    return generateKeys(length);
}
