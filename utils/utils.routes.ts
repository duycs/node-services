import express, { Request, Response } from "express"
import { StatusCodes } from "http-status-codes"
import * as rsa from "./rsa"

export const utilRoutes = express.Router()

utilRoutes.get("/ping", async (req : Request, res : Response) => {
    return res.status(StatusCodes.OK).json({"ok": "test"})
})

utilRoutes.post("/rsa/keys", async (req : Request, res : Response) => {
    try {
        const { length } = req.body;

        const data = await rsa.genKeys(length);
        
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

        const data = await rsa.encrypt(payload, publicKey);

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

        const data = await rsa.decrypt(payload, privateKey);

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

        const data = await rsa.sign(payload, privateKey);

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

        const success = await rsa.verify(payload, signature, publicKey);

        if (!success) {
            return res.status(StatusCodes.BAD_REQUEST).json({message : `Invalid data`})
        }

        return res.status(StatusCodes.OK).json({success})
    } catch (error) {
        return res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({error})
    }
})