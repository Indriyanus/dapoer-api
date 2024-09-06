import { Request, Response, NextFunction } from "express";
import { prisma } from "../../connection/index";
import jwt from "jsonwebtoken";

export const profile = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) throw { message: "Unauthorized", status: 401 };

    const decoded: any = jwt.verify(token, "dpng2024");
    const user = await prisma.pengguna.findUnique({
      where: {
        id: parseInt(decoded.userId),
      },
    });

    if (!user) throw { message: "User not found", status: 404 };

    res.status(200).send({
      error: false,
      message: "Profile fetched successfully",
      data: {
        namaDepan: user.namaDepan,
        namaBelakang: user.namaBelakang,
        NIK: user.NIK,
        email: user.email,
        tanggalLahir: user.tanggalLahir,
        posisi: user.posisi,
        nomorTelepon: user.nomorTelepon,
        alamat: user.alamat,
      },
    });
  } catch (error) {
    next(error);
  }
};
