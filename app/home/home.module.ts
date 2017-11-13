import { NgModule, NO_ERRORS_SCHEMA } from "@angular/core";
import { NativeScriptModule } from "nativescript-angular/nativescript.module";
import { NativeScriptUISideDrawerModule } from "nativescript-pro-ui/sidedrawer/angular";
import { NativeScriptUIListViewModule } from "nativescript-pro-ui/listview/angular";
import { NativeScriptUICalendarModule } from "nativescript-pro-ui/calendar/angular";
import { NativeScriptUIChartModule } from "nativescript-pro-ui/chart/angular";
import { NativeScriptUIDataFormModule } from "nativescript-pro-ui/dataform/angular";
import { NativeScriptUIAutoCompleteTextViewModule } from "nativescript-pro-ui/autocomplete/angular";
import { NativeScriptUIGaugesModule } from "nativescript-pro-ui/gauges/angular";
import { NativeScriptFormsModule } from "nativescript-angular/forms";

import { HomeRoutingModule } from "./home-routing.module";
import { HomeComponent } from "./home.component";

@NgModule({
    imports: [
        NativeScriptUISideDrawerModule,
        NativeScriptUIListViewModule,
        NativeScriptUICalendarModule,
        NativeScriptUIChartModule,
        NativeScriptUIDataFormModule,
        NativeScriptUIAutoCompleteTextViewModule,
        NativeScriptUIGaugesModule,
        NativeScriptModule,
        HomeRoutingModule,
        NativeScriptFormsModule
    ],
    declarations: [
        HomeComponent
    ],
    schemas: [
        NO_ERRORS_SCHEMA
    ]
})
export class HomeModule { }
