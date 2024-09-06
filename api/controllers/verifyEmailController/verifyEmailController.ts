import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { prisma } from "../../connection/index";
import bcrypt from "bcrypt";

export const verifyEmail = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const { token, newPassword } = req.body;
        if (!token || !newPassword) throw { message: "Token and new password are required", status: 400 };

        const decoded: any = jwt.verify(token, "secret_verification_key");
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        const user = await prisma.pengguna.update({
            where: {
                id: decoded.userId,
            },
            data: {
                kataSandi: hashedPassword
            }
        });

        res.status(200).send({
            error: false,
            message: "Email verified and password set successfully",
            data: user
        });
    } catch (error: any) {
        console.error("Verification error: ", error);
        res.status(500).send({
            error: true,
            message: "Email verification failed",
            details: error.message
        });
    }
};
