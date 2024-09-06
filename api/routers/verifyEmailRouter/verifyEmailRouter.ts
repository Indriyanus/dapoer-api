import { Router } from "express";
import {verifyEmail} from "../../controllers/verifyEmailController/verifyEmailController";
const router = Router()

router.post("/", verifyEmail )

export default router