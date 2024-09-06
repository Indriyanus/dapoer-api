import { Request, Response, NextFunction } from "express";
import prisma from "../../prisma";
import {comparePassword} from "../../helper/hashPassword";
import {createToken} from "../../helper/createToken";

export const login = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const { NIK, email, username, password } = req.body;

        const findUser = await prisma.pengguna.findFirst({
            where: {
                AND: [
                    { NIK: NIK },
                    { email: email },
                    { namaDepan: username }
                ]
            }
        });

        if (!findUser) throw { message: "Username & Password Doesn't Match", status: 401 };

        const isPasswordMatch = await comparePassword(password, findUser.kataSandi);
        if (!isPasswordMatch) throw { message: "Password Doesn't Match!", status: 401 };

        const token = createToken({ userId: findUser.id.toString(), userRole: findUser.posisi });

        res.status(200).send({
            error: false,
            message: "Authentication Success!",
            data: {
                token
            }
        });
    } catch (error) {
        console.error("Login error:", error);
        next(error);
    }
};
