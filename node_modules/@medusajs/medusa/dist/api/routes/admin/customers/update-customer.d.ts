/**
 * @oas [post] /customers/{id}
 * operationId: "PostCustomersCustomer"
 * summary: "Update a Customer"
 * description: "Updates a Customer."
 * x-authenticated: true
 * parameters:
 *   - (path) id=* {string} The ID of the Customer.
 *   - (query) expand {string} (Comma separated) Which fields should be expanded in each customer.
 *   - (query) fields {string} (Comma separated) Which fields should be retrieved in each customer.
 * requestBody:
 *   content:
 *     application/json:
 *       schema:
 *         properties:
 *           email:
 *             type: string
 *             description: The Customer's email.
 *             format: email
 *           first_name:
 *             type: string
 *             description:  The Customer's first name.
 *           last_name:
 *             type: string
 *             description:  The Customer's last name.
 *           phone:
 *             type: string
 *             description: The Customer's phone number.
 *           password:
 *             type: string
 *             description: The Customer's password.
 *             format: password
 *           groups:
 *             type: array
 *             items:
 *               required:
 *                 - id
 *               properties:
 *                 id:
 *                   description: The ID of a customer group
 *                   type: string
 *             description: A list of customer groups to which the customer belongs.
 *           metadata:
 *             description: An optional set of key-value pairs to hold additional information.
 *             type: object
 * x-codeSamples:
 *   - lang: JavaScript
 *     label: JS Client
 *     source: |
 *       import Medusa from "@medusajs/medusa-js"
 *       const medusa = new Medusa({ baseUrl: MEDUSA_BACKEND_URL, maxRetries: 3 })
 *       // must be previously logged in or use api token
 *       medusa.admin.customers.update(customer_id, {
 *         first_name: 'Dolly'
 *       })
 *       .then(({ customer }) => {
 *         console.log(customer.id);
 *       });
 *   - lang: Shell
 *     label: cURL
 *     source: |
 *       curl --location --request POST 'https://medusa-url.com/admin/customers/{id}' \
 *       --header 'Authorization: Bearer {api_token}' \
 *       --header 'Content-Type: application/json' \
 *       --data-raw '{
 *           "first_name": "Dolly"
 *       }'
 * security:
 *   - api_token: []
 *   - cookie_auth: []
 * tags:
 *   - Customer
 * responses:
 *   200:
 *     description: OK
 *     content:
 *       application/json:
 *         schema:
 *           properties:
 *             customer:
 *               $ref: "#/components/schemas/customer"
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
declare class Group {
    id: string;
}
export declare class AdminPostCustomersCustomerReq {
    email?: string;
    first_name?: string;
    last_name?: string;
    password?: string;
    phone?: string;
    metadata?: Record<string, unknown>;
    groups?: Group[];
}
