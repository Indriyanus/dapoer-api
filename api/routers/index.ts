import {NextFunction, Request, Response, Router} from "express";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import multer from "multer";
import path from "path";
import fs from "fs";
import {PrismaClient} from "@prisma/client";
import * as process from "node:process";
import {put} from "@vercel/blob";

const router = Router();
const nodemailer =  require("nodemailer")

const profile = async (req: Request, res: Response, next: NextFunction) => {
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

const createToken = ({userId, userRole}: {userId: string, userRole: string}) => {
    return jwt.sign({userId, userRole}, "dpng2024", {algorithm: "HS256", expiresIn: "1d"})
}

const saltRound = 10

const prisma = new PrismaClient({ log: ['query', 'info', 'warn', 'error'] });

const hashPassword = async(password: string) => {
    return await bcrypt.hash(password,saltRound)
}

const comparePassword = async (passwordReq: string, passwordDb: string) => {
    return await bcrypt.compare(passwordReq, passwordDb);
}

const position = async(req: Request, res: Response, next: NextFunction) => {
    try {
        const positions = [
            "STAFF",
            "LEADER",
            "ASMAN",
            "MANAGER",
            "DIREKTUR_OPERASIONAL",
            "KOMISARIS",
            "CEO"
        ];
        res.status(200).json({ positions });
    } catch (error) {
        next(error)
    }
}

const checkLogin = (req: Request, res: Response, next: NextFunction) => {
    const token = req.headers.authorization?.split(" ")[1];

    if (!token) {
        return next();
    }

    jwt.verify(token, "dpng2024", (err, decoded) => {
        if (err) {
            return next();
        }

        return res.status(403).json({ message: "You are already logged in" });
    });
};

const loginValidation = (req: Request, res: Response, next: NextFunction) => {
    try {
        const { username, password } =  req.body

        if(!username || !password) throw { message: "Username & Password is Required!", status: 401 }

        next()
    } catch (error) {
        next(error)
    }
}

const login = async (req: Request, res: Response, next: NextFunction) => {
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

const getUserProfile = async (req: Request, res: Response, next: NextFunction) => {
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
                    // url: `http://localhost:2024/public/profile-images/${user.profileImage.name}`, // Pastikan URL benar
                    url: user.profileImage.url,
                } : null,
            },
        });
    } catch (error) {
        next(error);
    }
};

const verifyEmail = async (req: Request, res: Response, next: NextFunction) => {
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

const getProducts = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const products = await prisma.product.findMany();
        res.status(200).json({
            error: false,
            message: "Products fetched successfully",
            data: products,
        });
    } catch (error) {
        next(error);
    }
};

const createMessage = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const { name, email, phone, product, message } = req.body;
        console.log('Received data:', { name, email, phone, product, message });

        const productData = await prisma.product.findFirst({
            where: {
                name: product,
            },
        });

        if (!productData) {
            console.log('Product not found');
            return res.status(400).json({ error: true, message: 'Product not found' });
        }

        const newMessage = await prisma.pesan.create({
            data: {
                name,
                email,
                phone,
                productName: product,
                message,
                productId: productData.id,
            },
        });

        res.status(201).json({
            error: false,
            message: 'Message sent successfully',
            data: newMessage,
        });
    } catch (error) {
        console.error('Error creating message:', error);
        res.status(500).json({ error: true, message: 'Internal Server Error' });
    }
}

const getMessages = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const messages = await prisma.pesan.findMany({
            include: { product: true },
        });
        res.status(200).json({
            error: false,
            message: "Messages fetched successfully",
            data: messages,
        });
    } catch (error) {
        next(error);
    }
};

const createDocument = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const { name, type, size, url, category, productCode } = req.body;
        console.log('Received data:', { name, type, size, url, category, productCode });

        if (category === 'Product') {
            // Temukan produk berdasarkan kode produk
            const productData = await prisma.product.findUnique({
                where: {
                    code: productCode,
                },
            });

            if (!productData) {
                console.log('Product not found');
                return res.status(400).json({ error: true, message: 'Product not found' });
            }

            // Buat dokumen baru untuk produk
            const newDocument = await prisma.document.create({
                data: {
                    name,
                    type,
                    size,
                    url,
                    category,
                    productId: productData.id,
                },
            });

            res.status(201).json({
                error: false,
                message: 'Document created successfully for product',
                data: newDocument,
            });

        } else if (category === 'Notadinas') {
            // Temukan notadinas berdasarkan kode notadinas
            const notadinasData = await prisma.notadinas.findUnique({
                where: {
                    code: productCode,
                },
            });

            if (!notadinasData) {
                console.log('Notadinas not found');
                return res.status(400).json({ error: true, message: 'Notadinas not found' });
            }

            // Buat dokumen baru untuk notadinas
            const newDocument = await prisma.document.create({
                data: {
                    name,
                    type,
                    size,
                    url,
                    category,
                    notadinasId: notadinasData.id,
                },
            });

            res.status(201).json({
                error: false,
                message: 'Document created successfully for notadinas',
                data: newDocument,
            });

        } else {
            return res.status(400).json({ error: true, message: 'Invalid category' });
        }
    } catch (error) {
        console.error('Error creating document:', error);
        res.status(500).json({ error: true, message: 'Internal Server Error' });
    }
};

const getDocuments = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const documents = await prisma.document.findMany({
            include: {
                product: true,
                notadinas: true,
            }
        });

        res.status(200).json({
            error: false,
            data: documents,
        });
    } catch (error) {
        console.error('Error fetching documents:', error);
        res.status(500).json({ error: true, message: 'Internal Server Error' });
    }
};

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const dir = path.join('/tmp');
        if (!fs.existsSync(dir)){
            fs.mkdirSync(dir, { recursive: true });
        }
        cb(null, dir);
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});

const uploadStatic = multer({ storage: storage });

const uploadBlobVercel = async (file: any, dir: string, base: string = 'files') => {
    return await put(`api/${base}/${dir}/${file.name}`, file, {
        access: 'public'
    })
}

const updateUserProfileImage = [
    uploadStatic.single('image'),
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

            const file = fs.createReadStream(req.file.path)

            const blob = await uploadBlobVercel(file, pengguna.id.toString(), 'profile-image')

            const newProfileImage = await prisma.profileImage.create({
                data: {
                    name: req.file.filename,
                    url: blob.url,
                    // url: req.file.path.replace(/\\/g, '/'), // Replacing backslashes with forward slashes
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

const uploadProfileImage = [
    uploadStatic.single('image'),
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
                include: { profileImage: true }
            });

            if (!pengguna) {
                return res.status(404).json({ error: true, message: 'User not found' });
            }

            // Hapus gambar profil lama jika ada
            if (pengguna.profileImage) {
            //     const oldImagePath = path.join(__dirname, 'public/uploads/profile-images/', pengguna.profileImage.name);
            //     if (fs.existsSync(oldImagePath)) {
            //         fs.unlinkSync(oldImagePath); // Hapus file lama
            //     }
            //
                // Hapus data gambar lama dari database
                await prisma.profileImage.delete({
                    where: { id: pengguna.profileImage.id }
                });
            }

            const file = fs.createReadStream(req.file.path)

            const blob = await uploadBlobVercel(file, pengguna.id.toString(), 'profile-image')

            // Simpan gambar baru
            const newProfileImage = await prisma.profileImage.create({
                data: {
                    name: req.file.filename,
                    url: blob.url,
                    // url: req.file.path.replace(/\\/g, '/'), // Mengganti backslashes dengan forward slashes
                    penggunaId: pengguna.id,
                },
            });

            res.status(201).json({
                error: false,
                message: 'Profile image updated successfully',
                data: newProfileImage,
            });
        } catch (error) {
            next(error);
        }
    }
];

const changePassword = async (req: Request, res: Response) => {
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
        const verificationLink = `${process.env.FRONT_END_URL}/confirmRegisterPassword?token=${verificationToken}`;
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

export const transporter = nodemailer.createTransport({
    service: "gmail",
    auth : {
        user: "ptdapoerpoesatnoesantaragroup@gmail.com",
        pass: "jtvrdcwdkrvsjvcg"
    },
    tls: {
        rejectUnauthorized: false
    }
})


// router.use("/login", loginRouter);
// router.use("/register", register);
// router.use("/positions", position);
// router.use("/profile", profileRouter);
// router.use("/user-profile", getUserProfile);
// router.use("/verify-email", verifyEmail);
// router.use("/products", productRouter);
// router.use("/contact", contactRouter);
// router.use("/messages", messageRouter);
// router.use("/documents", documentRouter);
// router.use("/menuprofile", menuProfileRouter);
// router.use("/profile-images", profileImageRouter);
// router.use("/change-password", changePasswordRouter);


router.post("/login/", checkLogin, loginValidation, login)
router.post("/register/", register)
router.get("/positions", position)
router.get("/profile/", profile)
router.get("/user-profile/", getUserProfile)
router.post("/verify-email/", verifyEmail )
router.get("/products/list", getProducts)
router.post("/contact/", createMessage)
router.get("/messages/", getMessages)
router.post("/documents/", createDocument)
router.get("/documents/", getDocuments)
router.get("/menuprofile/", getUserProfile)
router.post("/menuprofile/upload", updateUserProfileImage); // Tambahkan POST di sini juga
router.post("/profile-images/upload", uploadProfileImage)
router.post("/change-password/", changePassword)

export default router;
