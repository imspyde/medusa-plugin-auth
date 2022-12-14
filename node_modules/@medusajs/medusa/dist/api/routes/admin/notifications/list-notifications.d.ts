/**
 * @oas [get] /notifications
 * operationId: "GetNotifications"
 * summary: "List Notifications"
 * description: "Retrieves a list of Notifications."
 * x-authenticated: true
 * parameters:
 *   - (query) offset=0 {integer} The number of notifications to skip before starting to collect the notifications set
 *   - (query) limit=50 {integer} The number of notifications to return
 *   - (query) fields {string} Comma separated fields to include in the result set
 *   - (query) expand {string} Comma separated fields to populate
 *   - (query) event_name {string} The name of the event that the notification was sent for.
 *   - (query) resource_type {string} The type of resource that the Notification refers to.
 *   - (query) resource_id {string} The ID of the resource that the Notification refers to.
 *   - (query) to {string} The address that the Notification was sent to. This will usually be an email address, but represent other addresses such as a chat bot user id
 *   - (query) include_resends {string} A boolean indicating whether the result set should include resent notifications or not
 * x-codeSamples:
 *   - lang: JavaScript
 *     label: JS Client
 *     source: |
 *       import Medusa from "@medusajs/medusa-js"
 *       const medusa = new Medusa({ baseUrl: MEDUSA_BACKEND_URL, maxRetries: 3 })
 *       // must be previously logged in or use api token
 *       medusa.admin.notifications.list()
 *       .then(({ notifications }) => {
 *         console.log(notifications.length);
 *       });
 *   - lang: Shell
 *     label: cURL
 *     source: |
 *       curl --location --request GET 'https://medusa-url.com/admin/notifications' \
 *       --header 'Authorization: Bearer {api_token}'
 * security:
 *   - api_token: []
 *   - cookie_auth: []
 * tags:
 *   - Notification
 * responses:
 *   200:
 *     description: OK
 *     content:
 *       application/json:
 *         schema:
 *           properties:
 *             notifications:
 *               type: array
 *               items:
 *                 $ref: "#/components/schemas/notification"
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
export declare class AdminGetNotificationsParams {
    limit?: number;
    offset?: number;
    fields?: string;
    expand?: string;
    event_name?: string;
    resource_type?: string;
    resource_id?: string;
    to?: string;
    include_resends?: string;
}
