import { Request, Response, NextFunction } from "express";
import { prisma } from "../../connection/index";
import jwt from "jsonwebtoken";
import multer from "multer";
import path from "path";
import fs from "fs";

export const getUserProfile = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) throw { message: "Unauthorized", status: 401 };

    const decoded: any = jwt.verify(token, "dpng2024");
    const user = await prisma.pengguna.findUnique({
      where: {
        id: parseInt(decoded.userId),
      },
      include: {
        profileImage: true,
      },
    });

    if (!user) throw { message: "User not found", status: 404 };

    res.status(200).send({
      error: false,
      message: "Profile fetched successfully",
      data: {
        id: user.id,
        namaDepan: user.namaDepan,
        namaBelakang: user.namaBelakang,
        NIK: user.NIK,
        email: user.email,
        tanggalLahir: user.tanggalLahir,
        posisi: user.posisi,
        nomorTelepon: user.nomorTelepon,
        alamat: user.alamat,
        profileImage: user.profileImage ? {
          url: `http://localhost:2024/uploads/profile-images/${user.profileImage.name}`, // Pastikan URL benar
        } : null,
      },
    });
  } catch (error) {
    next(error);
  }
};

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const dir = path.join(__dirname, '../../../public/uploads/profile-images');
    if (!fs.existsSync(dir)){
        fs.mkdirSync(dir, { recursive: true });
    }
    cb(null, dir);
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + path.extname(file.originalname));
  }
});

const upload = multer({ storage: storage });

export const updateUserProfileImage = [
  upload.single('image'),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { penggunaId } = req.body;
      if (!penggunaId) {
        return res.status(400).json({ error: true, message: 'penggunaId is missing' });
      }

      if (!req.file) {
        return res.status(400).json({ error: true, message: 'No file uploaded' });
      }

      const pengguna = await prisma.pengguna.findUnique({
        where: { id: Number(penggunaId) },
      });

      if (!pengguna) {
        return res.status(404).json({ error: true, message: 'User not found' });
      }

      const newProfileImage = await prisma.profileImage.create({
        data: {
          name: req.file.filename,
          url: req.file.path.replace(/\\/g, '/'), // Replacing backslashes with forward slashes
          penggunaId: pengguna.id,
        },
      });

      res.status(201).json({
        error: false,
        message: 'Profile image uploaded successfully',
        data: newProfileImage,
      });
    } catch (error) {
      next(error);
    }
  }
];
