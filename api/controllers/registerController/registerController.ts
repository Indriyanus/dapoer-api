import { Request, Response, NextFunction } from "express";
import { prisma } from "../../connection/index";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { transporter } from "@/helper/transporter";

export const register = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const { firstName, lastName, NIK, email, birthday, phoneNumber, password, position, address } = req.body;

        // Mendapatkan token dari header
        const token = req.headers.authorization?.split(" ")[1];
        if (!token) throw { message: "Unauthorized", status: 401 };

        // Memverifikasi token dan mendapatkan data pengguna yang sedang login
        const decoded: any = jwt.verify(token, "dpng2024");
        const loggedInUser = await prisma.pengguna.findUnique({
            where: {
                id: parseInt(decoded.userId),
            },
        });

        if (!loggedInUser) throw { message: "User not found", status: 404 };

        // Logika privilege berdasarkan posisi
        const allowedPositions: { [key: string]: string[] } = {
            CEO: ["STAFF", "LEADER", "ASMAN", "MANAGER", "DIREKTUR_OPERASIONAL", "KOMISARIS", "CEO"],
            KOMISARIS: ["STAFF", "LEADER", "ASMAN", "MANAGER", "DIREKTUR_OPERASIONAL", "KOMISARIS"],
            DIREKTUR_OPERASIONAL: ["STAFF", "LEADER", "ASMAN", "MANAGER", "DIREKTUR_OPERASIONAL"],
            MANAGER: ["STAFF", "LEADER", "ASMAN", "MANAGER"]
        };

        const userPosition = loggedInUser.posisi;
        const canCreatePosition = allowedPositions[userPosition]?.includes(position);

        if (!canCreatePosition) {
            return res.status(403).send({
                error: true,
                message: `Privilege Anda tidak punya hak untuk create posisi ${position}`
            });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create user
        const newUser = await prisma.pengguna.create({
            data: {
                namaDepan: firstName,
                namaBelakang: lastName,
                NIK,
                email,
                tanggalLahir: new Date(birthday),
                posisi: position,
                kataSandi: hashedPassword,
                nomorTelepon: phoneNumber,
                alamat: address
            }
        });

        // Generate verification token
        const verificationToken = jwt.sign({ userId: newUser.id }, "secret_verification_key", { expiresIn: "1d" });

        // Send verification email
        const verificationLink = `http://localhost:3000/confirmRegisterPassword?token=${verificationToken}`;
        await transporter.sendMail({
            to: email,
            subject: "Email Verification - PT Dapoer Poesat Noesantara Group",
            html: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #ddd; border-radius: 10px; background-color: #f9f9f9;">
                <h2 style="text-align: center; color: #333;">Email Verification</h2>
                <p style="text-align: center; color: #555;">
                    Please click the button below to verify your email address and set your password.
                </p>
                <div style="text-align: center; margin: 20px 0;">
                    <a href="${verificationLink}" style="background-color: #d4b185; color: #fff; padding: 10px 20px; text-decoration: none; border-radius: 5px; font-weight: bold;">
                        Verify Email Address
                    </a>
                </div>
                <p style="text-align: center; color: #999; font-size: 12px;">
                    If you did not create an account, no further action is required.
                </p>
                <p style="text-align: center; color: #999; font-size: 12px;">
                    &copy; 2024 PT Dapoer Poesat Noesantara Group. All rights reserved.
                </p>
            </div>`
        });

        res.status(201).send({
            error: false,
            message: "User registered successfully. Please check your email to verify your account.",
            data: newUser
        });
    } catch (error: any) {
        console.error("Registration error: ", error);
        res.status(500).send({
            error: true,
            message: "Registration failed",
            details: error.message
        });
    }
};
