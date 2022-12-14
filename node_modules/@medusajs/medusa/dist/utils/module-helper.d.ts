import { ModuleResolution } from "../types/global";
import { ModulesResponse } from "../types/modules";
export declare class ModulesHelper {
    private modules_;
    setModules(modules: Record<string, ModuleResolution>): void;
    get modules(): ModulesResponse;
}
