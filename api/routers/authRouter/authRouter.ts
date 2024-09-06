import { Router } from "express";
import {getUserProfile} from "../../controllers/authController/authController";
const router = Router()

router.get("/", getUserProfile)

export default router