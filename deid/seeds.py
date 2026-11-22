"""Identity seeds derived from the corpus layout and a manual review of it.

Everything here is matched case-insensitively with word/camel-case
boundaries; see match.py. Discovered identities (metadata authors, user
folders, e-mails, ...) are added at run time by discover.py.
"""
import re

# source owner names that are also ordinary words or tool names: they are
# replaced in the owner path segment but not in file contents
OWNER_PATH_ONLY = {"freecad", "winder", "ecto", "case06", "person343", "desireloft",
                   "firestorm108", "studentreps", "episource", "ludex"}

# organisations, companies, labs, universities, brands
ORGS = """
Aarhus Universitet|Aarhus University|Aarhus|Arctic Research Center|Arctic Research Centre
AWI|Alfred Wegener|AdReNa|BAM Berlin|Buildlog|CNR-STIIMA|STIIMA|FabCity Hamburg|Fab City Hamburg
Curious Community Labs|LOCILAMP|LBNL|Lawrence Berkeley|LulzBot|Aleph Objects|Muzi Works
NIST|usnistgov|National Institute of Standards and Technology|NTNU|Open Source Ecology|OpenSourceEcology
OST|Ostschweizer Fachhochschule|Open Lab Automata|Pipettin|EPFL|IIT Kanpur|IITK|RWTH Aachen|RWTH
TU Delft|TUDelft|UKCEH|UNH|University of New Hampshire|Ljubljana|University Ljubljana|University Michigan
University of Michigan|University Southampton|University of Southampton|University Stuttgart
University of Stuttgart|Vhéliotech|Vheliotech|vhélio|ZSW|HyFaB|Allied-Signal|AlliedSignal|Drexel
Drexel University|DULOGO|dulogo|Heriot_Watt|Heriot-Watt|Heriot Watt|Purdue|Sandia|UIUC|Daratech
giclLogo|gicl|cranefield|Cranfield|Bentley Systems|LIGO|Caltech|UCLA|ETHZ|ETH Zurich|RobotX
Imperial College London|ImperialCollegeLondon|IIT|Istituto Italiano di Tecnologia|icub-tech-iit
robotology|DTU|DTUOpenAM|Toyota|Adafruit|Seeed Studio|Seeed|Sienci|Sienci Labs|Robolink
Zubax|Kurokesu|Antmicro|Elphel|Sovol|HighTorque|High Torque Robotics|RealMan|ROBOTIS|Keychron
Nespresso|Prusa|Prusa Research|Brompton|Shinano Kenshi|Teenage Engineering|Thorlabs|Festo|Misumi
Haas Automation|Sherline|ShopBot|Little Machine Shop|LittleMachineShop|Titans of CNC|TitansofCNC
Apogee Rockets|ITW Welding|Miller Electric|Cortona3D|Motedis|Darley|Valqua|Samcon|Mantion|Ritron
Marco Inc|marco-inc|Ulrich Rapp|ulrich-rapp|Journeyman's Workshop|journeymans-workshop|NEME-S|neme-s
modelesavapeur|Modeles a Vapeur|TU Chemnitz|tu-chemnitz|soumard|Stuart Models|stuartmodels|Buildlog.net
Franka Emika|Franka|Intel RealSense|hardgate|Bitcraze|Betrusted|Foundation Devices|FracktalWorks
Fracktal Works|FlySorter|OpenAgricultureFoundation|Open Agriculture Foundation|OpenwaterHealth
Openwater|PacktPublishing|Packt|PTC-Education|PathOn-AI|PathOn|RespiraWorks|RepRapPro|Roboy
Roshan-Industries|Roshan Industries|SeeMeCNC|seemecnc|Source-Robotics|Source Robotics|SpaceTeam
Ultimaker|VoronDesign|Voron Design|Zealandia-Systems|Zealandia Systems|BrayEngineering|Bray Engineering
COSMIIC|CharaChorder|ContinuumRoboticsLab|Expatria-Technologies|Expatria|Fabricatable-Machines
Fabricatable Machines|fellesverkstedet|Global-Health-Engineering|Global Health Engineering|GanzingerLab
Ganzinger|Haifa3D|IRNAS|KRSSG|MillenniumMachines|Millennium Machines|NRC-NANOmi|NeLy-EPFL|NimbRo
ONEARMY|One Army|Open-Lab-Starter-Kit|OrigamiRobotics|Pinbot-factory|ProjectFabMX|RavenLRS|RealManRobot
Roboparty|SeedMint|Seeed-Projects|uStepper|WuLab|V3lectronics|antmicro|asimovinc|Asimov Inc|bcn3d
BCN3D Technologies|Fundació CIM|machineagency|Machine Agency|menloresearch|Menlo Research|mesoSPIM
nakujaproject|Nakuja|nasa-jpl|NASA JPL|Jet Propulsion Laboratory|NASA|open-dynamic-robot-initiative
ODRI|openAMRobot|openppg|OpenPPG|opensourceimaging|Open Source Imaging|openwave-labs|orcahand|ORCA Hand
pachterlab|Pachter Lab|partcad|polvinc|rt-net|RT Corporation|uasal|uw-biorobotics|BioRobotics Lab
virtualagc|wuji-technology|Wuji|xolotl-hub|grablab|GRAB Lab|gramaziokohler|Gramazio Kohler
hoogenboom-group|losonczylab|Losonczy|wilsonlab|dholab|BrainCOGS|BLINCdev|BLINC Lab|Bento Arm
CIF-Cold-Stage|AutodeskAILab|Autodesk AI Lab|4Pi-SMS-consortium|ARIG-Robotique|ARIG|Adam-CAD
Armchair-Heavy-Industries|Armchair Heavy Industries|BasedHardware|Based Hardware|BenchCAD-org|BenchCAD
Ccct|Dacongan|Ice-Citron|Intrinsically-Sublime|Kentucky-ai|MetalWorkerTools|Sunny-Hack|Pinbot
aiaaUCmerced|UC Merced|igdtuw|IGDTUW|team751|tertiarycourses|Tertiary Courses|tm2space|arc-ens
cmuphyscomp|eMotres|eai-yeslab|effibot|evadne|fab-machines|htx-studio|huggingface|Hugging Face
input-inc|iotdesignshop|jitx-inc|JITX|materializr-cad|mekanika-dev|Mekanika|modernecotech|obotx
omicronrobot|sonicavionics|stadtulm|OSU-USLI-18|Oregon State|RWU-R2M|Phersax|MrAsana|AMBER Lab
Glowforge|Precious Plastic|precious-plastic|Dassault Falcon
"""

# person names / handles visible in folder names
PEOPLE = """
Dominique Lachiver|Lachiver|Maximilian Behm|Behm|Maxwell Lohss|Lohss|Manfred_Osti|Manfred Osti
Sanjeev_Trika|Sanjeev Trika|Randy_Wilson|Randy Wilson|CICIRELLO|Cicirello|sbrooks1|sbrooks2
regli|foralex|Huruy_H|Huruy|Guilherme|Bishwajeet|Jeremy|Himalia|Ziegler|Bill_Regli|Bill Regli
Pete_Brown|Pete Brown|Tom_Kramer|Tom Kramer|Kramer|Gaithersburg|Edmund_Optics|Edmund Optics
Fischer_Elektronik|Fischer Elektronik|Keysight_Instruments|Keysight|Lorenzetti|Okika
"""

# identifying project / product names
PROJECTS = """
OpenLoong|QingLoong|Qinglong|青龙|PAROL6|Faze4|SSG-48|Stealthburner|Moveo|BCN3DSigma|BCN3DSigmax
BCN3DPlus|IndyMill|PrintNC|ShapeOko|Jubilee|science-jubilee|OpenSaint|KORUZA|GoodEnoughCNC|Humphrey2
Passport-Prime|Passport Prime|RapidTool|K2TIRF|Panthera-HT|Panthera|Atom01|OpenLPBF|OpenLIFU|Open-LIFU
Open-LUFU|openlifu|openmotion|CADAM|IDEALEEU|Bento-Arm|ZRAD|LaRossa3D|OSREngines|build123d|CadQuarry
TseNC|Milo-V2.0|Milo-v1.5|milo-v1|Huxley|Ormerod|Olsryd-Whirlwind|Olsryd|myxa|opengrab|PIHTI|Catch5Yeah
HEMY|NanoMi|DrawMind3D|nimbro-op2|sciurus17|crane_x7|CRANE-X7|CRANE_X7|KXR|icub|iCub|ergoCub|ergocub
asimov-1|Asimov_1|ASV1|OpenWing|uHoubolt|Seek-CAD|reBot|reBot-DevArm|Star-Arm|AMBER_B1|Dracarys
Dracarys_5J|FabMX|OpenCR|raven2|romibo|OLSK|Fusion360GalleryDataset|openag|DexHand|dexhand|orcahand
ORCA_v1|BiDexHand|openamr|openwave|OpenSEM|OpenATC|fluxpad|megaruptor|XATC|Aetheris|materializr
draftwright|cosi-measure|OpenRiggingPlate|OpenSourceRail|OpenMotor|OpenEAI|betrusted|Neuropixels
mesoSPIM|ENZEL|visebase|modulathe|kbd2600|ZACplus|upklib|noBS-CAD|HatsuHand|HatsuMuv|DAPP
SV06|Pivot-Lock|newton-instrumentation|HexaHive|Anduril|openFrame|opentakeoff|OpenSourceLeg
LearningTower|learning-tower|Remorque PM|PowerCube6|PowerCube|CEB Press|ThrowBot|Tiny Oat Collider
FENRIR|Trillium II|Pipettin-bot|pipettin-bot|diot-crate|wr-switch|OpenClawd|clawdsolana|Plug.ar
LOCILAMP|lerobot|cadgenbench|benchcad|MAPLEHardware
Pyramid-PCB-Inspection|smb_assembly_manual|openhand-hardware|iris-hw|loong|Loong
"""

GENERIC_STOP = {
    "omi", "iris", "craft", "tegu", "dapp", "arig", "ost", "odri", "iit", "unh", "zsw", "bam", "awi",
}


def _split(block):
    out = []
    for line in block.strip().splitlines():
        out.extend(x.strip() for x in line.split("|") if x.strip())
    return out


def seed_terms():
    terms = set()
    for t in _split(ORGS) + _split(PEOPLE) + _split(PROJECTS):
        terms.add(t)
    return terms


OWNER_RE = re.compile(r"^(?:sources/github|archives)/([^/]+?)__")
GITLAB_RE = re.compile(r"^sources/gitlab/gitlab\.com__([^/]+?)__")


def owners_from_paths(paths):
    owners = set()
    for p in paths:
        m = OWNER_RE.match(p) or GITLAB_RE.match(p)
        if m:
            owners.add(m.group(1))
    return owners


def domains_from_paths(paths):
    doms = set()
    for p in paths:
        s = p.split("/")
        if len(s) > 2 and s[0] == "sources" and s[1] in ("web", "catalog") and "." in s[2] and " " not in s[2]:
            doms.add(s[2])
    return doms
