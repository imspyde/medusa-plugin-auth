/**
 * @oas [get] /auth/{email}
 * operationId: "GetAuthEmail"
 * summary: "Check if email exists"
 * description: "Checks if a Customer with the given email has signed up."
 * parameters:
 *   - in: path
 *     name: email
 *     schema:
 *       type: string
 *       format: email
 *     required: true
 *     description: The email to check if exists.
 * x-codeSamples:
 *   - lang: JavaScript
 *     label: JS Client
 *     source: |
 *       import Medusa from "@medusajs/medusa-js"
 *       const medusa = new Medusa({ baseUrl: MEDUSA_BACKEND_URL, maxRetries: 3 })
 *       medusa.auth.exists('user@example.com')
 *   - lang: Shell
 *     label: cURL
 *     source: |
 *       curl --location --request GET 'https://medusa-url.com/store/auth/user@example.com' \
 *       --header 'Cookie: connect.sid={sid}'
 * tags:
 *   - Auth
 * responses:
 *  "200":
 *    description: OK
 *    content:
 *      application/json:
 *        schema:
 *          properties:
 *            exists:
 *              type: boolean
 *              description: Whether email exists or not.
 *  "400":
 *    $ref: "#/components/responses/400_error"
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
