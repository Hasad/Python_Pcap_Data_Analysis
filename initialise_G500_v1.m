%% Initialisation code for Gulfstream G500 model 
%
%   All parameters in metric units unless stated otherwise
%
%   Mudassir Lone       12 Sept 2018

% clear %%
clc

% Initialise and run model

filename.model = 'G500_model_v4.slx';
filename.data = 'sim_data_v8.mat';


%Load bus definition

disp('Loading bus definitions...');
load('Cranfield_Aircraft_Model_Interface_Bus_Def.mat');
load('Cranfield_Aircraft_Interface_Configuration.mat');

% Load look up table data
disp('Loading aerodynamic data...')
load(filename.data);

geo.Sref = 101.7;% Wing reference area
geo.Cref = 6.06;% Mean aero chord
geo.Bref = 27.12;% Reference span
geo.Engine = [0 2 0];% Engine position [x y z] relative to nose
geo.Inertia = [initialise.Ixx 0 initialise.Ixz
    0 initialise.Iyy 0
    initialise.Ixz 0 initialise.Izz];% Aircraft inertia properties


% Engine data
engine.MaxThrust = 100000; % Newtons
engine.Timeconstant = 0.3; % seconds
engine.SFC = 0.35;
engine.ThrustRatio = 0.9;

% Define initial conditions
disp('Loading initial flight conditions...')
simsetup.Mach = 0.5;
simsetup.altitude = 22000*0.3048;
simsetup.mass = 30000;
simsetup.CG = 11.375;% CG relative to nose
simsetup.g = 9.81;
simsetup.turb = zeros(1,6);

% Define initial conditions
simsetup.alpha =  0;
simsetup.TAS =  156.2085;%m/s
simsetup.Thrust = 1.0427e4;%N
simsetup.XYZ = [0 0 -simsetup.altitude];
simsetup.UVW = [simsetup.TAS*cos(simsetup.alpha) 0 simsetup.TAS*sin(simsetup.alpha)];
simsetup.Euler = [0 simsetup.alpha 0];

disp('Aircraft model initialised.')