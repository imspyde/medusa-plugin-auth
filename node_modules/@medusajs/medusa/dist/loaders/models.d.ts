import { ClassConstructor, MedusaContainer } from "../types/global";
import { EntitySchema } from "typeorm";
/**
 * Registers all models in the model directory
 */
declare const _default: ({ container }: {
    container: MedusaContainer;
}, config?: {
    register: boolean;
}) => (EntitySchema<any> | ClassConstructor<unknown>)[];
export default _default;
