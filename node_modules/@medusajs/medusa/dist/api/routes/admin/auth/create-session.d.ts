/**
 * @oas [post] /auth
 * operationId: "PostAuth"
 * summary: "User Login"
 * x-authenticated: false
 * description: "Logs a User in and authorizes them to manage Store settings."
 * parameters:
 *   - (body) email=* {string} The User's email.
 *   - (body) password=* {string} The User's password.
 * requestBody:
 *   content:
 *     application/json:
 *       schema:
 *         required:
 *           - email
 *           - password
 *         properties:
 *           email:
 *             type: string
 *             description: The User's email.
 *             format: email
 *           password:
 *             type: string
 *             description: The User's password.
 *             format: password
 * x-codeSamples:
 *   - lang: JavaScript
 *     label: JS Client
 *     source: |
 *       import Medusa from "@medusajs/medusa-js"
 *       const medusa = new Medusa({ baseUrl: MEDUSA_BACKEND_URL, maxRetries: 3 })
 *       medusa.admin.auth.createSession({
 *         email: 'user@example.com',
 *         password: 'supersecret'
 *       }).then((({ user }) => {
 *         console.log(user.id);
 *       });
 *   - lang: Shell
 *     label: cURL
 *     source: |
 *       curl --location --request POST 'https://medusa-url.com/admin/auth' \
 *       --header 'Content-Type: application/json' \
 *       --data-raw '{
 *         "email": "user@example.com",
 *         "password": "supersecret"
 *       }'
 * tags:
 *   - Auth
 * responses:
 *  "200":
 *    description: OK
 *    content:
 *      application/json:
 *        schema:
 *          properties:
 *            user:
 *              $ref: "#/components/schemas/user"
 *  "400":
 *    $ref: "#/components/responses/400_error"
 *  "401":
 *    $ref: "#/components/responses/incorrect_credentials"
 *  "404":
 *    $ref: "#/components/responses/not_found_error"
 *  "409":
 *    $ref: "#/components/responses/invalid_state_error"
 *  "422":
 *    $ref: "#/components/responses/invalid_request_error"
 *  "500":
 *    $ref: "#/components/responses/500_error"
 */
declare const _default: (req: any, res: any) => Promise<void>;
export default _default;
export declare class AdminPostAuthReq {
    email: string;
    password: string;
}
