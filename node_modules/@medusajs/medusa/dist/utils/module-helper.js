"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ModulesHelper = void 0;
var ModulesHelper = /** @class */ (function () {
    function ModulesHelper() {
        this.modules_ = {};
    }
    ModulesHelper.prototype.setModules = function (modules) {
        this.modules_ = modules;
    };
    Object.defineProperty(ModulesHelper.prototype, "modules", {
        get: function () {
            return Object.values(this.modules_ || {}).map(function (value) { return ({
                module: value.definition.key,
                resolution: value.resolutionPath,
            }); });
        },
        enumerable: false,
        configurable: true
    });
    return ModulesHelper;
}());
exports.ModulesHelper = ModulesHelper;
//# sourceMappingURL=module-helper.js.map