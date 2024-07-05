import express, { Request, Response } from "express"
import { StatusCodes } from "http-status-codes"
import * as rsa from "./rsa"

export const utilRoutes = express.Router()

utilRoutes.get("/ping", async (req : Request, res : Response) => {
    return res.status(StatusCodes.OK).json({"ok": "test"})
})

utilRoutes.post("/to-string", async (req : Request, res : Response) => {
    const { data } = req.body;

    return res.status(StatusCodes.OK).json({"data": rsa.toString(data)})
})

utilRoutes.post("/to-base64", async (req : Request, res : Response) => {
    const { data } = req.body;

    return res.status(StatusCodes.OK).json({"data": rsa.toBase64(data)})
})

utilRoutes.post("/rsa/keys", async (req : Request, res : Response) => {
    try {
        const { length } = req.body;

        const { publicKey, privateKey } = rsa.genKeys(length);

        const data = { "publicKey": rsa.toBase64(publicKey), "privateKey": rsa.toBase64(privateKey)};
        
        if (!data) {
            return res.status(StatusCodes.BAD_REQUEST).json({message : `Invalid data`})
        }

        return res.status(StatusCodes.OK).json({data})
    } catch (error) {
        return res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({error})
    }
})

utilRoutes.post("/rsa/encrypt", async (req : Request, res : Response) => {
    try {
        const { payload, publicKey } = req.body;

        const data = rsa.encrypt(payload, rsa.toString(publicKey));

        if (!data) {
            return res.status(StatusCodes.BAD_REQUEST).json({message : `Invalid data`})
        }

        return res.status(StatusCodes.OK).json({data})
    } catch (error) {
        return res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({error})
    }
})

utilRoutes.post("/rsa/decrypt", async (req : Request, res : Response) => {
    try {
        const { payload, privateKey } = req.body

        const data = rsa.decrypt(payload, rsa.toString(privateKey));

        if (!data) {
            return res.status(StatusCodes.BAD_REQUEST).json({message : `Invalid data`})
        }

        return res.status(StatusCodes.OK).json({data})
    } catch (error) {
        return res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({error})
    }
})

utilRoutes.post("/rsa/sign", async (req : Request, res : Response) => {
    try {
        const { payload, privateKey } = req.body

        const data = rsa.sign(payload, rsa.toString(privateKey));

        if (!data) {
            return res.status(StatusCodes.BAD_REQUEST).json({message : `Invalid data`})
        }

        return res.status(StatusCodes.OK).json({data})
    } catch (error) {
        return res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({error})
    }
})


utilRoutes.post("/rsa/verify", async (req : Request, res : Response) => {
    try {
        const { payload, signature, publicKey } = req.body

        const success = rsa.verify(payload, signature, rsa.toString(publicKey));

        if (!success) {
            return res.status(StatusCodes.BAD_REQUEST).json({success: success, message : `Invalid data`})
        }

        return res.status(StatusCodes.OK).json({success})
    } catch (error) {
        return res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({error})
    }
})