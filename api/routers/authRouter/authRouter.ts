import { Router } from "express";
const router = Router()
import {getUserProfile} from "@/controllers/authController/authController"


router.get("/", getUserProfile)

export default router