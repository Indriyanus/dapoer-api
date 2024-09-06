import Router from "express"
const router = Router()
import { position } from "@/controllers/positionController/positionController"

router.get("/", position)

export default router