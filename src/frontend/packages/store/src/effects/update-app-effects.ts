import { Injectable } from '@angular/core';
import { Http } from '@angular/http';
import { Actions, Effect, ofType } from '@ngrx/effects';
import { mergeMap } from 'rxjs/operators';

import {
  AppMetadataTypes,
  GetAppEnvVarsAction,
  GetAppStatsAction,
  GetAppSummaryAction,
} from '../../../cloud-foundry/src/actions/app-metadata.actions';
import { UPDATE_SUCCESS, UpdateExistingApplication } from '../../../cloud-foundry/src/actions/application.actions';
import { WrapperRequestActionSuccess } from '../types/request.types';
import { entityCatalogue } from '../../../core/src/core/entity-catalogue/entity-catalogue.service';
import { STRATOS_ENDPOINT_TYPE } from '../../../core/src/base-entity-schemas';
import { appStatsEntityType, appSummaryEntityType } from '../../../cloud-foundry/src/cf-entity-factory';



@Injectable()
export class UpdateAppEffects {

  constructor(
    private http: Http,
    private actions$: Actions
  ) {
  }

  @Effect() UpdateAppInStore$ = this.actions$.pipe(
    ofType<WrapperRequestActionSuccess>(UPDATE_SUCCESS),
    mergeMap((action: WrapperRequestActionSuccess) => {
      const updateAction = action.apiAction as UpdateExistingApplication;
      const updateEntities = updateAction.updateEntities || [AppMetadataTypes.ENV_VARS, AppMetadataTypes.STATS, AppMetadataTypes.SUMMARY];
      const actions = [];
      updateEntities.forEach(updateEntity => {
        switch (updateEntity) {
          case AppMetadataTypes.ENV_VARS:
            // This is done so the app metadata env vars environment_json matches that of the app
            actions.push(new GetAppEnvVarsAction(action.apiAction.guid, action.apiAction.endpointGuid as string));
            break;
          case AppMetadataTypes.STATS:
            const appStatsEntity = entityCatalogue.getEntity(STRATOS_ENDPOINT_TYPE, appStatsEntityType);
            const appStatsActionBuilder = appStatsEntity.actionOrchestrator.getActionBuilder('get');
            const statsAction  = appStatsActionBuilder(action.apiAction.guid, action.apiAction.endpointGuid as string);
            // Application has changed and the associated app stats need to also be updated.
            // Apps that are started can just make the stats call to update cached stats, however this call will fail for stopped apps.
            // For those cases create a fake stats request response that should result in the same thing
            if (updateAction.newApplication.state === 'STOPPED') {
              actions.push(new WrapperRequestActionSuccess({ entities: {}, result: [] }, statsAction, 'fetch', 0, 0));
            } else {
              actions.push(statsAction);
            }
            break;
          case AppMetadataTypes.SUMMARY:
            const appSummaryEntity = entityCatalogue.getEntity(STRATOS_ENDPOINT_TYPE, appSummaryEntityType);
            const appSummaryActionBuilder = appSummaryEntity.actionOrchestrator.getActionBuilder('get');
            const getAppSummaryAction = appSummaryActionBuilder(action.apiAction.guid, action.apiAction.endpointGuid as string);
            actions.push(getAppSummaryAction);
            break;
        }
      });


      return actions;
    }));

}
