/**
 * @oas [post] /customers/password-token
 * operationId: PostCustomersCustomerPasswordToken
 * summary: Request Password Reset
 * description: "Creates a reset password token to be used in a subsequent /reset-password request. The password token should be sent out of band e.g. via email and will not be returned."
 * requestBody:
 *   content:
 *     application/json:
 *       schema:
 *         required:
 *           - email
 *         properties:
 *           email:
 *             description: "The email of the customer."
 *             type: string
 *             format: email
 * x-codeSamples:
 *   - lang: JavaScript
 *     label: JS Client
 *     source: |
 *       import Medusa from "@medusajs/medusa-js"
 *       const medusa = new Medusa({ baseUrl: MEDUSA_BACKEND_URL, maxRetries: 3 })
 *       medusa.customers.generatePasswordToken({
 *         email: 'user@example.com'
 *       })
 *       .then(() => {
 *         // successful
 *       })
 *       .catch(() => {
 *         // failed
 *       })
 *   - lang: Shell
 *     label: cURL
 *     source: |
 *       curl --location --request POST 'https://medusa-url.com/store/customers/password-token' \
 *       --header 'Content-Type: application/json' \
 *       --data-raw '{
 *           "email": "user@example.com"
 *       }'
 * tags:
 *   - Customer
 * responses:
 *   204:
 *     description: OK
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
export declare class StorePostCustomersCustomerPasswordTokenReq {
    email: string;
}
