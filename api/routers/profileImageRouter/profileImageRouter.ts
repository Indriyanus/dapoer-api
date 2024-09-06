import { Router } from "express";
import {uploadProfileImage} from "../../controllers/profileImageController/profileImageController";

const router = Router();

router.post("/upload", uploadProfileImage);

export default router;
