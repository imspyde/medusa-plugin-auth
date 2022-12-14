/**
 * @oas [post] /shipping-options/{id}
 * operationId: "PostShippingOptionsOption"
 * summary: "Update Shipping Option"
 * description: "Updates a Shipping Option"
 * x-authenticated: true
 * parameters:
 *   - (path) id=* {string} The ID of the Shipping Option.
 * requestBody:
 *   content:
 *     application/json:
 *       schema:
 *         required:
 *           - requirements
 *         properties:
 *           name:
 *             description: "The name of the Shipping Option"
 *             type: string
 *           amount:
 *             description: "The amount to charge for the Shipping Option."
 *             type: integer
 *           admin_only:
 *             description: "If true, the option can be used for draft orders"
 *             type: boolean
 *           metadata:
 *             description: "An optional set of key-value pairs with additional information."
 *             type: object
 *           requirements:
 *             description: "The requirements that must be satisfied for the Shipping Option to be available."
 *             type: array
 *             items:
 *               required:
 *                 - type
 *                 - amount
 *               properties:
 *                 id:
 *                   description: The ID of the requirement
 *                   type: string
 *                 type:
 *                   description: The type of the requirement
 *                   type: string
 *                   enum:
 *                     - max_subtotal
 *                     - min_subtotal
 *                 amount:
 *                   description: The amount to compare with.
 *                   type: integer
 *           includes_tax:
 *             description: "[EXPERIMENTAL] Tax included in prices of shipping option"
 *             type: boolean
 * x-codeSamples:
 *   - lang: JavaScript
 *     label: JS Client
 *     source: |
 *       import Medusa from "@medusajs/medusa-js"
 *       const medusa = new Medusa({ baseUrl: MEDUSA_BACKEND_URL, maxRetries: 3 })
 *       // must be previously logged in or use api token
 *       medusa.admin.shippingOptions.update(option_id, {
 *         name: 'PostFake',
 *         requirements: [
 *           {
 *             id,
 *             type: 'max_subtotal',
 *             amount: 1000
 *           }
 *         ]
 *       })
 *       .then(({ shipping_option }) => {
 *         console.log(shipping_option.id);
 *       });
 *   - lang: Shell
 *     label: cURL
 *     source: |
 *       curl --location --request POST 'https://medusa-url.com/admin/shipping-options/{id}' \
 *       --header 'Authorization: Bearer {api_token}' \
 *       --header 'Content-Type: application/json' \
 *       --data-raw '{
 *           "requirements": [
 *             {
 *               "type": "max_subtotal",
 *               "amount": 1000
 *             }
 *           ]
 *       }'
 * security:
 *   - api_token: []
 *   - cookie_auth: []
 * tags:
 *   - Shipping Option
 * responses:
 *   200:
 *     description: OK
 *     content:
 *       application/json:
 *         schema:
 *           properties:
 *             shipping_option:
 *               $ref: "#/components/schemas/shipping_option"
 *   "400":
 *     $ref: "#/components/responses/400_error"
 *   "401":
 *     $ref: "#/components/responses/unauthorized"
 *   "404":
 *     $ref: "#/components/responses/not_found_error"
 *   "409":
 *     $ref: "#/components/responses/invalid_state_error"
 *   "422":
 *     $ref: "#/components/responses/invalid_request_error"
 *   "500":
 *     $ref: "#/components/responses/500_error"
 */
declare const _default: (req: any, res: any) => Promise<void>;
export default _default;
declare class OptionRequirement {
    id: string;
    type: string;
    amount: number;
}
export declare class AdminPostShippingOptionsOptionReq {
    name: string;
    amount?: number;
    requirements: OptionRequirement[];
    admin_only?: boolean;
    metadata?: Record<string, unknown>;
    includes_tax?: boolean;
}
