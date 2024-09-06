import { Router } from "express";
const router = Router()

import { register } from "@/controllers/registerController/registerController";

router.post("/", register)

export default router
