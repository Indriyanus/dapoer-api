import { Router } from "express";
import {register} from "tsconfig-paths";
const router = Router()

router.post("/", register)

export default router
