import { Router } from "express";
const router = Router();

import loginRouter from "./loginRouter/loginRouter";
import {register} from "tsconfig-paths";
import {position} from "../controllers/positionController/positionController";
import profileRouter from "./profileRouter/profileRouter";
import {getUserProfile} from "../controllers/authController/authController";
import {verifyEmail} from "../controllers/verifyEmailController/verifyEmailController";
import productRouter from "./productRouter/productRouter";
import contactRouter from "./contactRouter/contactRouter";
import messageRouter from "./messageRouter/messageRouter";
import documentRouter from "./documentRouter/documentRouter";
import menuProfileRouter from "./menuProfileRouter/menuProfileRouter";
import profileImageRouter from "./profileImageRouter/profileImageRouter";
import changePasswordRouter from "./changePasswordRouter/changePasswordRouter";

router.use("/login", loginRouter);
router.use("/register", register);
router.use("/positions", position);
router.use("/profile", profileRouter);
router.use("/user-profile", getUserProfile);
router.use("/verify-email", verifyEmail);
router.use("/products", productRouter);
router.use("/contact", contactRouter);
router.use("/messages", messageRouter);
router.use("/documents", documentRouter);
router.use("/menuprofile", menuProfileRouter);
router.use("/profile-images", profileImageRouter);
router.use("/change-password", changePasswordRouter);

export default router;
