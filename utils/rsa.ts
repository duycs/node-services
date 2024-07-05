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

	const publicKey = toBase64(data.publicKey);
	const privateKey = toBase64(data.privateKey);

	return {publicKey, privateKey};
}

const encryptedData = (data: any, publicKey: string) => crypto.publicEncrypt(
	{
		key: publicKey,
		//padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
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

const signature = (verifiableData: any, privateKey: string) => crypto.sign("sha256", Buffer.from(verifiableData), {
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

const dataBase64 = (data: any) => {
    return Buffer.from(data).toString("base64");
}

export const encrypt  = (data : string, publicKey: string) => {
    return dataBase64(encryptedData(data, publicKey));
}

export const decrypt  = (data : string, privateKey: string) => {
    return decryptedData(data, privateKey).toString();
}

export const verify  = (data : string, signature : string, publicKey: string) => {
    return isVerified(data, signature, publicKey);
}

export const sign  = (data : string, privateKey: string) => {
    return dataBase64(signature(data, privateKey));
}

export const toBase64  = (data : string) => {
    return dataBase64(data);
}

export const genKeys = (length: number) => {
    return generateKeys(length);
}
