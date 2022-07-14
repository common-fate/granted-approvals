/**
 * Generated by orval v6.8.1 🍺
 * Do not edit manually.
 * Approvals
 * Granted Approvals API
 * OpenAPI spec version: 1.0
 */
import {
  rest
} from 'msw'
import {
  faker
} from '@faker-js/faker'
import {
  RequestStatus,
  ApprovalMethod,
  AccessRuleStatus
} from '.././types'

export const getUserListRequestsUpcomingMock = () => ({requests: [...Array(faker.datatype.number({min: 1, max: 10}))].map(() => ({id: faker.random.word(), requestor: faker.random.word(), status: faker.random.arrayElement(Object.values(RequestStatus)), reason: faker.random.arrayElement([faker.random.word(), undefined]), timing: {durationSeconds: faker.datatype.number(), startTime: faker.random.arrayElement([faker.random.word(), undefined])}, requestedAt: faker.random.word(), accessRule: {id: faker.random.word(), version: faker.random.word()}, updatedAt: faker.random.word(), grant: faker.random.arrayElement([{status: faker.random.arrayElement(['PENDING','ACTIVE','ERROR','REVOKED','EXPIRED']), subject: faker.internet.email(), provider: faker.random.word(), start: faker.random.word(), end: faker.random.word()}, undefined]), approvalMethod: faker.random.arrayElement([faker.random.arrayElement(Object.values(ApprovalMethod)), undefined])})), next: faker.random.arrayElement([faker.random.word(), null])})

export const getUserListRequestsPastMock = () => ({requests: [...Array(faker.datatype.number({min: 1, max: 10}))].map(() => ({id: faker.random.word(), requestor: faker.random.word(), status: faker.random.arrayElement(Object.values(RequestStatus)), reason: faker.random.arrayElement([faker.random.word(), undefined]), timing: {durationSeconds: faker.datatype.number(), startTime: faker.random.arrayElement([faker.random.word(), undefined])}, requestedAt: faker.random.word(), accessRule: {id: faker.random.word(), version: faker.random.word()}, updatedAt: faker.random.word(), grant: faker.random.arrayElement([{status: faker.random.arrayElement(['PENDING','ACTIVE','ERROR','REVOKED','EXPIRED']), subject: faker.internet.email(), provider: faker.random.word(), start: faker.random.word(), end: faker.random.word()}, undefined]), approvalMethod: faker.random.arrayElement([faker.random.arrayElement(Object.values(ApprovalMethod)), undefined])})), next: faker.random.arrayElement([faker.random.word(), null])})

export const getAdminArchiveAccessRuleMock = () => ({id: faker.random.word(), version: faker.random.word(), status: faker.random.arrayElement(Object.values(AccessRuleStatus)), groups: [...Array(faker.datatype.number({min: 1, max: 10}))].map(() => (faker.random.word())), approval: {users: [...Array(faker.datatype.number({min: 1, max: 10}))].map(() => (faker.random.word())), groups: [...Array(faker.datatype.number({min: 1, max: 10}))].map(() => (faker.random.word()))}, name: faker.random.word(), description: faker.random.word(), metadata: {createdAt: faker.random.word(), createdBy: faker.random.word(), updatedAt: faker.random.word(), updatedBy: faker.random.word(), updateMessage: faker.random.arrayElement([faker.random.word(), undefined])}, target: {provider: {id: faker.random.word(), type: faker.random.word()}, with: {
        'cl5kmqvwq00075mxdgkmf31ui': faker.random.word()
      }}, timeConstraints: {maxDurationSeconds: faker.datatype.number()}, isCurrent: faker.datatype.boolean()})

export const getListProvidersMock = () => ([...Array(faker.datatype.number({min: 1, max: 10}))].map(() => ({id: faker.random.word(), type: faker.random.word()})))

export const getGetProviderMock = () => ({id: faker.random.word(), type: faker.random.word()})

export const getGetProviderArgsMock = () => ({})

export const getListProviderArgOptionsMock = () => ({hasOptions: faker.datatype.boolean(), options: [...Array(faker.datatype.number({min: 1, max: 10}))].map(() => ({label: faker.random.word(), value: faker.random.word()}))})

export const getDefaultMSW = () => [
rest.get('*/api/v1/requests/upcoming', (_req, res, ctx) => {
        return res(
          ctx.delay(1000),
          ctx.status(200, 'Mocked status'),
ctx.json(getUserListRequestsUpcomingMock()),
        )
      }),rest.get('*/api/v1/requests/past', (_req, res, ctx) => {
        return res(
          ctx.delay(1000),
          ctx.status(200, 'Mocked status'),
ctx.json(getUserListRequestsPastMock()),
        )
      }),rest.post('*/api/v1/admin/access-rules/:ruleId/archive', (_req, res, ctx) => {
        return res(
          ctx.delay(1000),
          ctx.status(200, 'Mocked status'),
ctx.json(getAdminArchiveAccessRuleMock()),
        )
      }),rest.get('*/api/v1/admin/providers', (_req, res, ctx) => {
        return res(
          ctx.delay(1000),
          ctx.status(200, 'Mocked status'),
ctx.json(getListProvidersMock()),
        )
      }),rest.get('*/api/v1/admin/providers/:providerId', (_req, res, ctx) => {
        return res(
          ctx.delay(1000),
          ctx.status(200, 'Mocked status'),
ctx.json(getGetProviderMock()),
        )
      }),rest.get('*/api/v1/admin/providers/:providerId/args', (_req, res, ctx) => {
        return res(
          ctx.delay(1000),
          ctx.status(200, 'Mocked status'),
ctx.json(getGetProviderArgsMock()),
        )
      }),rest.get('*/api/v1/admin/providers/:providerId/args/:argId/options', (_req, res, ctx) => {
        return res(
          ctx.delay(1000),
          ctx.status(200, 'Mocked status'),
ctx.json(getListProviderArgOptionsMock()),
        )
      }),]
