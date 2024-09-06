import { Router } from "express";
const router = Router()

import { verifyEmail } from "@/controllers/verifyEmailController/verifyEmailController"; 

router.post("/", verifyEmail )

export default router