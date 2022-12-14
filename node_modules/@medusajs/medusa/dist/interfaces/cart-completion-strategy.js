"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.isCartCompletionStrategy = exports.AbstractCartCompletionStrategy = void 0;
var AbstractCartCompletionStrategy = /** @class */ (function () {
    function AbstractCartCompletionStrategy() {
    }
    return AbstractCartCompletionStrategy;
}());
exports.AbstractCartCompletionStrategy = AbstractCartCompletionStrategy;
function isCartCompletionStrategy(obj) {
    return (typeof obj.complete === "function" ||
        obj instanceof AbstractCartCompletionStrategy);
}
exports.isCartCompletionStrategy = isCartCompletionStrategy;
//# sourceMappingURL=cart-completion-strategy.js.map