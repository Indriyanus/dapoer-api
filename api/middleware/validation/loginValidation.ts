import { NextFunction, Request, Response } from "express";

export const loginValidation = (req: Request, res: Response, next: NextFunction) => {
    try {
        const { username, password } =  req.body

        if(!username || !password) throw { message: "Username & Password is Required!", status: 401 }

        next()
    } catch (error) {
        next(error)
    }
}