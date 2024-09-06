import { Request, Response } from "express";
import { prisma } from "../../connection";
import jwt from "jsonwebtoken";
import {comparePassword, hashPassword} from "../../helper/hashPassword";

export const changePassword = async (req: Request, res: Response) => {
    try {
        const { oldPassword, newPassword } = req.body;
        const token = req.headers.authorization?.split(" ")[1];

        if (!token) {
            return res.status(401).json({ error: true, message: "Unauthorized" });
        }

        const decoded: any = jwt.verify(token, "dpng2024");

        const user = await prisma.pengguna.findUnique({
            where: { id: parseInt(decoded.userId) }
        });

        if (!user) {
            return res.status(404).json({ error: true, message: "User not found" });
        }

        const isPasswordMatch = await comparePassword(oldPassword, user.kataSandi);
        if (!isPasswordMatch) {
            return res.status(400).json({ error: true, message: "Old password doesn't match" });
        }

        const hashedPassword = await hashPassword(newPassword);

        await prisma.pengguna.update({
            where: { id: user.id },
            data: { kataSandi: hashedPassword }
        });

        res.status(200).json({ error: false, message: "Password changed successfully" });
    } catch (error) {
        res.status(500).json({ error: true, message: "Internal Server Error" });
    }
};
