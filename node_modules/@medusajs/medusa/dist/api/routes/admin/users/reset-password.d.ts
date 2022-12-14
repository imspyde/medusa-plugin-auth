/**
 * @oas [post] /users/reset-password
 * operationId: "PostUsersUserPassword"
 * summary: "Reset Password"
 * description: "Sets the password for a User given the correct token."
 * x-authenticated: true
 * requestBody:
 *   content:
 *     application/json:
 *       schema:
 *         required:
 *           - token
 *           - password
 *         properties:
 *           email:
 *             description: "The Users email."
 *             type: string
 *             format: email
 *           token:
 *             description: "The token generated from the 'password-token' endpoint."
 *             type: string
 *           password:
 *             description: "The Users new password."
 *             type: string
 *             format: password
 * x-codeSamples:
 *   - lang: JavaScript
 *     label: JS Client
 *     source: |
 *       import Medusa from "@medusajs/medusa-js"
 *       const medusa = new Medusa({ baseUrl: MEDUSA_BACKEND_URL, maxRetries: 3 })
 *       // must be previously logged in or use api token
 *       medusa.admin.users.resetPassword({
 *         token: 'supersecrettoken',
 *         password: 'supersecret'
 *       })
 *       .then(({ user }) => {
 *         console.log(user.id);
 *       });
 *   - lang: Shell
 *     label: cURL
 *     source: |
 *       curl --location --request POST 'https://medusa-url.com/admin/users/reset-password' \
 *       --header 'Authorization: Bearer {api_token}' \
 *       --header 'Content-Type: application/json' \
 *       --data-raw '{
 *           "token": "supersecrettoken",
 *           "password": "supersecret"
 *       }'
 * security:
 *   - api_token: []
 *   - cookie_auth: []
 * tags:
 *   - User
 * responses:
 *   200:
 *     description: OK
 *     content:
 *       application/json:
 *         schema:
 *           properties:
 *             user:
 *               $ref: "#/components/schemas/user"
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
export declare type payload = {
    email: string;
    user_id: string;
    password: string;
};
export declare class AdminResetPasswordRequest {
    email?: string;
    token: string;
    password: string;
}
