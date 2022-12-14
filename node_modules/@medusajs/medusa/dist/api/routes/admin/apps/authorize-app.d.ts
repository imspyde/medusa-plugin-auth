/**
 * @oas [post] /apps/authorizations
 * operationId: "PostApps"
 * summary: "Generate Token for App"
 * description: "Generates a token for an application."
 * x-authenticated: true
 * requestBody:
 *   content:
 *     application/json:
 *       schema:
 *         required:
 *           - application_name
 *           - state
 *           - code
 *         properties:
 *           application_name:
 *             type: string
 *             description:  Name of the application for the token to be generated for.
 *           state:
 *             type: string
 *             description: State of the application.
 *           code:
 *             type: string
 *             description: The code for the generated token.
 * x-codeSamples:
 *   - lang: Shell
 *     label: cURL
 *     source: |
 *       curl --location --request POST 'https://medusa-url.com/admin/apps/authorizations' \
 *       --header 'Authorization: Bearer {api_token}' \
 *       --header 'Content-Type: application/json' \
 *       --data-raw '{
 *           "application_name": "example",
 *           "state": "ready",
 *           "code": "token"
 *       }'
 * security:
 *   - api_token: []
 *   - cookie_auth: []
 * tags:
 *   - App
 * responses:
 *  "200":
 *    description: OK
 *    content:
 *      application/json:
 *        schema:
 *          properties:
 *            apps:
 *              $ref: "#/components/schemas/OAuth"
 *  "400":
 *    $ref: "#/components/responses/400_error"
 *  "401":
 *    $ref: "#/components/responses/unauthorized"
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
export declare class AdminPostAppsReq {
    application_name: string;
    state: string;
    code: string;
}
