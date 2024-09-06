import { Router } from "express";
import {getUserProfile} from "../../controllers/authController/authController";
import {updateUserProfileImage} from "../../controllers/menuProfileController/menuProfileController";


const router = Router();

router.get("/", getUserProfile);
router.post("/upload", updateUserProfileImage); // Tambahkan POST di sini juga

export default router;
