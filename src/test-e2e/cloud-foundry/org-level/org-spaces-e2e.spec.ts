import { browser, promise } from 'protractor';

import { IOrganization } from '../../../frontend/app/core/cf-api.types';
import { APIResource } from '../../../frontend/app/store/types/api.types';
import { e2e, E2ESetup } from '../../e2e';
import { E2EConfigCloudFoundry } from '../../e2e.types';
import { CFHelpers } from '../../helpers/cf-helpers';
import { ConsoleUserType, E2EHelpers } from '../../helpers/e2e-helpers';
import { ListComponent } from '../../po/list.po';
import { CfOrgLevelPage } from './cf-org-level-page.po';

const customOrgSpacesLabel = E2EHelpers.e2eItemPrefix + (process.env.CUSTOM_APP_LABEL || process.env.USER) + '-org-spaces-test-';

fdescribe('Org Spaces - ', () => {

  let e2eSetup: E2ESetup;
  let cfHelper: CFHelpers;
  let defaultCf: E2EConfigCloudFoundry;
  let orgPage: CfOrgLevelPage;
  const spaceList = new ListComponent();

  function createSpaceNames(count: number): string[] {
    const spaceNames = [];
    for (let i = 0; i < count; i++) {
      spaceNames.push(E2EHelpers.createCustomName(customOrgSpacesLabel + i));
    }
    return spaceNames;
  }

  function chainCreateSpace(endpointGuid: string, org: APIResource<IOrganization>, spaceNames: string[]): promise.Promise<any> {
    return spaceNames.reduce((promiseChain, name) => {
      return promiseChain.then(() => {
        // Ensure there's a gap so that the 'created_at' is different
        browser.sleep(1100);
        return cfHelper.addSpaceIfMissingForEndpointUsers(
          endpointGuid,
          org.metadata.guid,
          org.entity.name,
          name,
          defaultCf);
      });
    }, promise.fullyResolved(''));
  }

  function concurrentCreateSpace(endpointGuid: string, org: APIResource<IOrganization>, spaceNames: string[]): promise.Promise<any> {
    return promise.all(spaceNames.map(name => cfHelper.addSpaceIfMissingForEndpointUsers(
      endpointGuid,
      org.metadata.guid,
      org.entity.name,
      name,
      defaultCf)));
  }

  function setup(spaceNames: string[], orderImportant: boolean) {
    defaultCf = e2e.secrets.getDefaultCFEndpoint();
    const endpointGuid = e2e.helper.getEndpointGuid(e2e.info, defaultCf.name);
    browser.wait(
      cfHelper.fetchOrg(endpointGuid, defaultCf.testOrg)
        .then((org: APIResource<IOrganization>) => {
          // Chain the creation of the spaces to ensure there's a nice sequential 'created_at' value
          const promises = orderImportant ?
            chainCreateSpace(endpointGuid, org, spaceNames) :
            concurrentCreateSpace(endpointGuid, org, spaceNames);

          return promises.then(() => org.metadata.guid);
        })
        .then(orgGuid => navToOrgSpaces(endpointGuid, orgGuid))
    );
  }

  function navToOrgSpaces(endpointGuid: string, orgGuid: string) {
    orgPage = CfOrgLevelPage.forEndpoint(endpointGuid, orgGuid);
    orgPage.navigateTo();
    orgPage.waitForPageOrChildPage();
    orgPage.loadingIndicator.waitUntilNotShown();
    orgPage.goToSpacesTab();
    expect(spaceList.isTableView()).toBeFalsy();
  }

  function tearDown(spaceNames: string[]) {
    const endpointGuid = e2e.helper.getEndpointGuid(e2e.info, defaultCf.name);
    spaceNames.forEach(name => cfHelper.deleteSpaceIfExisting(endpointGuid, name));
  }

  beforeAll(() => {
    e2eSetup = e2e.setup(ConsoleUserType.admin)
      .clearAllEndpoints()
      .registerDefaultCloudFoundry()
      .connectAllEndpoints(ConsoleUserType.admin)
      .loginAs(ConsoleUserType.admin)
      .getInfo();
    cfHelper = new CFHelpers(e2eSetup);
  });

  describe('No Pages -', () => {
    const orgName = customOrgSpacesLabel;
    let endpointGuid;
    beforeAll(() => {
      defaultCf = e2e.secrets.getDefaultCFEndpoint();
      endpointGuid = e2e.helper.getEndpointGuid(e2e.info, defaultCf.name);
      // Create a temporary org which will contain no spaces
      browser.wait(cfHelper.addOrgIfMissingForEndpointUsers(endpointGuid, defaultCf, orgName));
    });

    beforeEach(() => {
      navToOrgSpaces(endpointGuid);
    });

    it('Should show message', () => {

    });

    afterAll(() => {
      const endpointGuid = e2e.helper.getEndpointGuid(e2e.info, defaultCf.name);
      cfHelper.deleteSpaceIfExisting(endpointGuid, orgName);
    });
  });

  describe('Single Page -', () => {

    let spaceNames;

    function testSortBy(sortFieldName: string) {
      const sortFieldForm = spaceList.header.getSortFieldForm();
      sortFieldForm.fill({ 'sort-field': sortFieldName });

      let expectedTitleOrder: string[];
      spaceList.cards.getCardsMetadata().then(cards => {
        const originalTitleOrder = cards.map(card => card.title);
        expectedTitleOrder = new Array(originalTitleOrder.length);
        for (let i = 0; i < originalTitleOrder.length; i++) {
          expectedTitleOrder[originalTitleOrder.length - i - 1] = originalTitleOrder[i];
        }
      });

      spaceList.header.toggleSortOrder();

      spaceList.cards.getCardsMetadata().then(cards => {
        const newTitleOrder = cards.map(card => card.title);
        expect(expectedTitleOrder).toEqual(newTitleOrder);
      });
    }

    beforeAll(() => {
      spaceNames = createSpaceNames(3);
      setup(spaceNames, true);
      expect(spaceList.getTotalResults()).toBeLessThanOrEqual(9);
      expect(spaceList.pagination.isDisplayed()).toBeFalsy();
    });

    afterAll(() => tearDown(spaceNames));


    it('sort by name', () => {
      testSortBy('Name');
    });

    it('sort by creation', () => {
      testSortBy('Creation');
    });

    it('text filter by existing', () => {
      // Clear and check initial cards
      spaceList.header.clearSearchText();
      expect(spaceList.header.getSearchText()).toBeFalsy();
      expect(spaceList.cards.getCardCount()).toBeGreaterThanOrEqual(spaceNames.length);

      // Apply filter
      const spaceToFind = spaceNames[2];
      spaceList.header.setSearchText(spaceToFind);

      // Check for single card
      expect(spaceList.header.getSearchText()).toEqual(spaceToFind);
      expect(spaceList.cards.getCardCount()).toBe(1);
      expect(spaceList.cards.findCardByTitle(spaceToFind)).toBeDefined();
    });

    it('text filter by non-existing', () => {
      // Clear and check initial cards
      spaceList.header.clearSearchText();
      expect(spaceList.header.getSearchText()).toBeFalsy();
      expect(spaceList.cards.getCardCount()).toBeGreaterThanOrEqual(spaceNames.length);

      // Apply filter
      const spaceToNotFind = 'sdfst4654324543224 s5d4x4g5g gdg4fdg 5fdg';
      spaceList.header.setSearchText(spaceToNotFind);

      // Check for zero cards
      expect(spaceList.header.getSearchText()).toEqual(spaceToNotFind);
      expect(spaceList.cards.getCardCount()).toBe(0);
    });

    it('single page pagination settings', () => {
      expect(spaceList.pagination.isDisplayed()).toBeFalsy();
    });

  });

  describe('Multi Page -', () => {

    let spaceNames;

    beforeAll(() => {
      spaceNames = createSpaceNames(11);
      setup(spaceNames, false);
      expect(spaceList.getTotalResults()).toBeGreaterThanOrEqual(spaceNames.length);

    });

    afterAll(() => tearDown(spaceNames));

    function testStartingPosition() {
      // General expects for all tests in this section
      expect(spaceList.getTotalResults()).toBeLessThan(80);
      expect(spaceList.pagination.isPresent()).toBeTruthy();

      expect(spaceList.cards.getCardCount()).toBe(9);
      expect(spaceList.pagination.getPageSize()).toEqual('9');
      expect(spaceList.pagination.getTotalResults()).toBeGreaterThan(9);
      expect(spaceList.pagination.getTotalResults()).toBeLessThanOrEqual(18);

      expect(spaceList.pagination.getNavFirstPage().getComponent().isEnabled()).toBeFalsy();
      expect(spaceList.pagination.getNavPreviousPage().getComponent().isEnabled()).toBeFalsy();
      expect(spaceList.pagination.getNavNextPage().getComponent().isEnabled()).toBeTruthy();
      expect(spaceList.pagination.getNavLastPage().getComponent().isEnabled()).toBeTruthy();
    }

    beforeEach(testStartingPosition);

    afterEach(testStartingPosition);

    it('Initial Pagination Values', () => { });

    it('Next and Previous Page', () => {
      spaceList.pagination.getNavNextPage().getComponent().click();

      expect(spaceList.pagination.getNavFirstPage().getComponent().isEnabled()).toBeTruthy();
      expect(spaceList.pagination.getNavPreviousPage().getComponent().isEnabled()).toBeTruthy();
      expect(spaceList.pagination.getNavNextPage().getComponent().isEnabled()).toBeFalsy();
      expect(spaceList.pagination.getNavLastPage().getComponent().isEnabled()).toBeFalsy();

      spaceList.pagination.getNavPreviousPage().getComponent().click();
    });

    it('Last and First Page', () => {
      spaceList.pagination.getNavLastPage().getComponent().click();

      expect(spaceList.pagination.getNavFirstPage().getComponent().isEnabled()).toBeTruthy();
      expect(spaceList.pagination.getNavPreviousPage().getComponent().isEnabled()).toBeTruthy();
      expect(spaceList.pagination.getNavNextPage().getComponent().isEnabled()).toBeFalsy();
      expect(spaceList.pagination.getNavLastPage().getComponent().isEnabled()).toBeFalsy();

      spaceList.pagination.getNavFirstPage().getComponent().click();
    });

    it('Change Page Size', () => {

      spaceList.pagination.setPageSize('80');
      expect(spaceList.cards.getCardCount()).toBeGreaterThan(9);

      expect(spaceList.pagination.getNavFirstPage().getComponent().isEnabled()).toBeFalsy();
      expect(spaceList.pagination.getNavPreviousPage().getComponent().isEnabled()).toBeFalsy();
      expect(spaceList.pagination.getNavNextPage().getComponent().isEnabled()).toBeFalsy();
      expect(spaceList.pagination.getNavLastPage().getComponent().isEnabled()).toBeFalsy();

      spaceList.pagination.setPageSize('9');
      expect(spaceList.cards.getCardCount()).toBe(9);

    });

  });

});

// TODO: RC empty list
