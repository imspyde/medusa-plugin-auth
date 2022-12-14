import { UserRoles } from "../../../../models/user";
/**
 * @oas [post] /invites
 * operationId: "PostInvites"
 * summary: "Create an Invite"
 * description: "Creates an Invite and triggers an 'invite' created event"
 * x-authenticated: true
 * requestBody:
 *   content:
 *     application/json:
 *       schema:
 *         required:
 *           - user
 *           - role
 *         properties:
 *           user:
 *             description: "The email for the user to be created."
 *             type: string
 *             format: email
 *           role:
 *             description: "The role of the user to be created."
 *             type: string
 *             enum: [admin, member, developer]
 * x-codeSamples:
 *   - lang: JavaScript
 *     label: JS Client
 *     source: |
 *       import Medusa from "@medusajs/medusa-js"
 *       const medusa = new Medusa({ baseUrl: MEDUSA_BACKEND_URL, maxRetries: 3 })
 *       // must be previously logged in or use api token
 *       medusa.admin.invites.create({
 *         user: "user@example.com",
 *         role: "admin"
 *       })
 *       .then(() => {
 *         // successful
 *       })
 *       .catch(() => {
 *         // an error occurred
 *       });
 *   - lang: Shell
 *     label: cURL
 *     source: |
 *       curl --location --request POST 'https://medusa-url.com/admin/invites' \
 *       --header 'Authorization: Bearer {api_token}' \
 *       --header 'Content-Type: application/json' \
 *       --data-raw '{
 *           "user": "user@example.com",
 *           "role": "admin"
 *       }'
 * security:
 *   - api_token: []
 *   - cookie_auth: []
 * tags:
 *   - Invite
 * responses:
 *   200:
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
export declare class AdminPostInvitesReq {
    user: string;
    role: UserRoles;
}
