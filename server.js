
const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { URL } = require("url");

const ROOT = __dirname;
const PUBLIC = path.join(ROOT, "public");
const DATA_DIR = path.join(ROOT, "data");
const DB_FILE = path.join(DATA_DIR, "db.json");
fs.mkdirSync(DATA_DIR, { recursive: true });

function readDB(){
  if(!fs.existsSync(DB_FILE)){
    const db = {
      users: [
        {id:"admin-001", role:"admin", name:"EMS Administrator", username:"admin", passwordHash:hashPassword("admin123")},
        {id:"principal-001", role:"principal", name:"Principal", username:"principal", passwordHash:hashPassword("principal123")},
        {id:"teacher-001", role:"teacher", name:"Demo Teacher", username:"teacher", passwordHash:hashPassword("teacher123"), approved:true},
        {id:"student-001", role:"student", name:"Demo Student", username:"student", passwordHash:hashPassword("demo123"), className:"9", section:"A", studentId:"EMS-9001"}
      ],
      students: [
        {id:"student-001", studentId:"EMS-9001", name:"Demo Student", className:"9", section:"A", attendance:94, overall:86, rank:3,
          subjects:[
            {name:"Mathematics", marks:91, total:100},
            {name:"Physics", marks:84, total:100},
            {name:"Chemistry", marks:79, total:100},
            {name:"English", marks:88, total:100},
            {name:"Computer Science", marks:93, total:100}
          ],
          notices:[{title:"Parent-Teacher Meeting", text:"Meeting scheduled for Friday at 10:00 AM."}]
        }
      ],
      teachers: [
        {userId:"teacher-001", subjects:["Physics","Mathematics"], classes:["9-A","8-B"], approved:true}
      ],
      notices:[
        {id:"n1",title:"Welcome to EMS",text:"School management portal is now online.",date:"2026-09-02"},
        {id:"n2",title:"Parent-Teacher Meeting",text:"Friday at 10:00 AM in the main hall.",date:"2026-09-02"}
      ]
    };
    writeDB(db); return db;
  }
  return JSON.parse(fs.readFileSync(DB_FILE,"utf8"));
}
function writeDB(db){ fs.writeFileSync(DB_FILE, JSON.stringify(db,null,2)); }
function hashPassword(password, salt){
  salt = salt || crypto.randomBytes(16).toString("hex");
  const derived = crypto.scryptSync(password, salt, 64).toString("hex");
  return `${salt}:${derived}`;
}
function verifyPassword(password, stored){
  const [salt, key] = String(stored||"").split(":");
  if(!salt || !key) return false;
  const derived = crypto.scryptSync(password, salt, 64).toString("hex");
  return crypto.timingSafeEqual(Buffer.from(key,"hex"), Buffer.from(derived,"hex"));
}
function parseBody(req){
  return new Promise((resolve,reject)=>{
    let data=""; req.on("data",c=>{data+=c; if(data.length>2e6) req.destroy();});
    req.on("end",()=>{try{resolve(data?JSON.parse(data):{});}catch(e){reject(e);}});
  });
}
function send(res,status,obj){res.writeHead(status,{"Content-Type":"application/json; charset=utf-8","Cache-Control":"no-store"});res.end(JSON.stringify(obj));}
function safeUser(u){ const {passwordHash,...x}=u; return x; }

const sessions = new Map();
function sessionUser(req){
  const token = (req.headers.cookie||"").match(/ems_session=([^;]+)/)?.[1];
  const uid = token && sessions.get(token);
  if(!uid) return null;
  const db=readDB(); return db.users.find(u=>u.id===uid)||null;
}
function requireRole(req,res,roles){
  const u=sessionUser(req);
  if(!u || (roles && !roles.includes(u.role))){send(res,401,{error:"Unauthorized"});return null;}
  return u;
}

async function api(req,res,url){
  const db=readDB();
  if(req.method==="POST" && url.pathname==="/api/signup"){
    const b=await parseBody(req);
    const role=["student","teacher"].includes(b.role)?b.role:null;
    if(!role || !b.name || !b.username || !b.password || b.password.length<6) return send(res,400,{error:"Name, username and password (6+ chars) are required."});
    if(db.users.some(u=>u.username.toLowerCase()===b.username.toLowerCase())) return send(res,409,{error:"Username already exists."});
    const id=crypto.randomUUID();
    const user={id,role,name:b.name,username:b.username,passwordHash:hashPassword(b.password)};
    if(role==="student"){user.className=b.className||"";user.section=b.section||"";user.studentId=b.studentId||("EMS-"+Math.floor(1000+Math.random()*9000));}
    else user.approved=false;
    db.users.push(user);
    if(role==="student"){
      db.students.push({id,studentId:user.studentId,name:user.name,className:user.className,section:user.section,attendance:0,overall:0,rank:"—",subjects:[],notices:[]});
    } else db.teachers.push({userId:id,subjects:[],classes:[],approved:false});
    writeDB(db);
    return send(res,201,{message:role==="teacher"?"Account created. Awaiting administrator approval.":"Account created. You can log in.",pending:role==="teacher"});
  }
  if(req.method==="POST" && url.pathname==="/api/login"){
    const b=await parseBody(req); const u=db.users.find(x=>x.username.toLowerCase()===String(b.username||"").toLowerCase());
    if(!u || !verifyPassword(String(b.password||""),u.passwordHash)) return send(res,401,{error:"Invalid username or password."});
    if(u.role==="teacher" && !u.approved) return send(res,403,{error:"Teacher account is awaiting approval."});
    const token=crypto.randomBytes(32).toString("hex"); sessions.set(token,u.id);
    res.setHeader("Set-Cookie",`ems_session=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=86400`);
    return send(res,200,{user:safeUser(u)});
  }
  if(req.method==="POST" && url.pathname==="/api/logout"){
    const token=(req.headers.cookie||"").match(/ems_session=([^;]+)/)?.[1]; if(token) sessions.delete(token);
    res.setHeader("Set-Cookie","ems_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0"); return send(res,200,{ok:true});
  }
  if(req.method==="GET" && url.pathname==="/api/me"){
    const u=sessionUser(req); return send(res,200,{user:u?safeUser(u):null});
  }
  if(req.method==="GET" && url.pathname==="/api/dashboard"){
    const u=requireRole(req,res); if(!u)return;
    if(u.role==="student"){ const s=db.students.find(x=>x.id===u.id); return send(res,200,{user:safeUser(u),student:s,notices:db.notices}); }
    if(u.role==="teacher"){ const t=db.teachers.find(x=>x.userId===u.id); return send(res,200,{user:safeUser(u),teacher:t,students:db.students,notices:db.notices}); }
    return send(res,200,{user:safeUser(u),students:db.students,teachers:db.teachers,notices:db.notices});
  }
  if(req.method==="POST" && url.pathname==="/api/students"){
    const u=requireRole(req,res,["coordinator","principal","admin"]); if(!u)return;
    const b=await parseBody(req);
    if(!b.name || !b.className || !b.section) return send(res,400,{error:"Student name, grade and section are required."});
    const studentId=String(b.studentId||("EMS-"+Math.floor(100000+Math.random()*900000))).trim();
    if(db.students.some(s=>String(s.studentId).toLowerCase()===studentId.toLowerCase())) return send(res,409,{error:"Student ID already exists."});
    const username=String(b.username||studentId).trim();
    if(db.users.some(x=>x.username.toLowerCase()===username.toLowerCase())) return send(res,409,{error:"Username already exists."});
    const password=String(b.password||"student123");
    if(password.length<6) return send(res,400,{error:"Password must be at least 6 characters."});
    const id=crypto.randomUUID();
    db.users.push({id,role:"student",name:String(b.name).trim(),username,passwordHash:hashPassword(password),className:String(b.className).trim(),section:String(b.section).trim(),studentId,fatherName:String(b.fatherName||"").trim()});
    db.students.push({id,studentId,name:String(b.name).trim(),fatherName:String(b.fatherName||"").trim(),className:String(b.className).trim(),section:String(b.section).trim(),attendance:0,overall:0,rank:"—",subjects:[],notices:[]});
    writeDB(db); return send(res,201,{message:"Student added successfully.",student:db.students[db.students.length-1]});
  }
  if(req.method==="POST" && url.pathname==="/api/students/import"){
    const u=requireRole(req,res,["coordinator","principal","admin"]); if(!u)return;
    const b=await parseBody(req); const rows=Array.isArray(b.rows)?b.rows:[]; if(!rows.length)return send(res,400,{error:"No student rows found."});
    const added=[],errors=[];
    for(let i=0;i<rows.length;i++){ const r=rows[i]||{}; const name=String(r.name||r["Student Name"]||"").trim(); const fatherName=String(r.fatherName||r["Father Name"]||"").trim(); const className=String(r.className||r.grade||r.Grade||"").trim(); const section=String(r.section||r.Section||"").trim(); const studentId=String(r.studentId||r["Student ID"]||("EMS-"+Math.floor(100000+Math.random()*900000))).trim(); if(!name||!className||!section){errors.push({row:i+2,error:"Name, grade and section are required"});continue;} if(db.students.some(s=>String(s.studentId).toLowerCase()===studentId.toLowerCase())||db.users.some(x=>x.username.toLowerCase()===studentId.toLowerCase())){errors.push({row:i+2,error:"Student ID already exists"});continue;} const id=crypto.randomUUID(); const username=String(r.username||studentId).trim(); const password=String(r.password||"student123"); if(db.users.some(x=>x.username.toLowerCase()===username.toLowerCase())){errors.push({row:i+2,error:"Username already exists"});continue;} db.users.push({id,role:"student",name,username,passwordHash:hashPassword(password),className,section,studentId,fatherName}); db.students.push({id,studentId,name,fatherName,className,section,attendance:0,overall:0,rank:"—",subjects:[],notices:[]}); added.push({name,studentId}); }
    writeDB(db); return send(res,201,{message:`Imported ${added.length} student(s).`,added,errors});
  }
  if(req.method==="GET" && url.pathname==="/api/students"){
    const u=requireRole(req,res,["teacher","coordinator","principal","admin"]); if(!u)return; return send(res,200,{students:db.students});
  }
  if(req.method==="PUT" && url.pathname.startsWith("/api/students/")){
    const u=requireRole(req,res,["teacher","coordinator","principal","admin"]); if(!u)return;
    const id=url.pathname.split("/").pop(); const s=db.students.find(x=>x.id===id); if(!s)return send(res,404,{error:"Student not found"});
    const b=await parseBody(req);
    if(u.role==="teacher"){
      const t=db.teachers.find(x=>x.userId===u.id);
      if(!t || !t.approved) return send(res,403,{error:"Not approved"});
    }
    if(b.attendance!==undefined)s.attendance=Math.max(0,Math.min(100,Number(b.attendance)));
    if(b.overall!==undefined)s.overall=Math.max(0,Math.min(100,Number(b.overall)));
    if(Array.isArray(b.subjects))s.subjects=b.subjects;
    writeDB(db); return send(res,200,{student:s});
  }
  if(req.method==="POST" && url.pathname==="/api/notices"){
    const u=requireRole(req,res,["teacher","coordinator","principal","admin"]); if(!u)return;
    const b=await parseBody(req); if(!b.title||!b.text)return send(res,400,{error:"Title and message required"});
    db.notices.unshift({id:crypto.randomUUID(),title:b.title,text:b.text,date:new Date().toISOString().slice(0,10),by:u.name});
    writeDB(db); return send(res,201,{ok:true});
  }
  if(req.method==="GET" && url.pathname==="/api/teachers/pending"){
    const u=requireRole(req,res,["admin","principal"]); if(!u)return;
    return send(res,200,{teachers:db.users.filter(x=>x.role==="teacher"&&!x.approved).map(safeUser)});
  }
  if(req.method==="POST" && url.pathname==="/api/teachers/approve"){
    const u=requireRole(req,res,["admin","principal"]); if(!u)return;
    const b=await parseBody(req); const t=db.users.find(x=>x.id===b.id&&x.role==="teacher"); if(!t)return send(res,404,{error:"Teacher not found"});
    t.approved=true; const td=db.teachers.find(x=>x.userId===t.id); if(td)td.approved=true; writeDB(db); return send(res,200,{ok:true});
  }
  if(req.method==="POST" && url.pathname==="/api/ai"){
    requireRole(req,res); if(!sessionUser(req))return;
    const b=await parseBody(req); const q=String(b.question||"").toLowerCase();
    let answer="Ask me about a school topic and I’ll explain it step-by-step in simple language.";
    if(q.includes("newton")||q.includes("third law"))answer="Newton’s 3rd Law: For every action, there is an equal and opposite reaction. Example: when you push the ground while jumping, the ground pushes you upward.";
    else if(q.includes("photosynthesis"))answer="Photosynthesis is how green plants make food using sunlight, carbon dioxide and water. Oxygen is released as a by-product.";
    else if(q.includes("dna"))answer="DNA is the molecule that stores genetic instructions. It is arranged as a double helix and contains bases A, T, C and G.";
    return send(res,200,{answer});
  }
  send(res,404,{error:"API route not found"});
}

function serveStatic(req,res,url){
  let p=url.pathname==="/" ? "/index.html" : url.pathname;
  p=path.normalize(p).replace(/^(\.\.[\/\\])+/, "");
  const file=path.join(PUBLIC,p);
  if(!file.startsWith(PUBLIC) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) return send(res,404,{error:"Not found"});
  const ext=path.extname(file).toLowerCase();
  const types={".html":"text/html; charset=utf-8",".css":"text/css; charset=utf-8",".js":"text/javascript; charset=utf-8",".jpg":"image/jpeg",".jpeg":"image/jpeg",".png":"image/png",".webp":"image/webp",".svg":"image/svg+xml",".ico":"image/x-icon"};
  res.writeHead(200,{"Content-Type":types[ext]||"application/octet-stream"});fs.createReadStream(file).pipe(res);
}

const server=http.createServer(async(req,res)=>{
  res.setHeader("X-Content-Type-Options","nosniff");
  res.setHeader("X-Frame-Options","SAMEORIGIN");
  res.setHeader("Referrer-Policy","strict-origin-when-cross-origin");
  try{
    const url=new URL(req.url,`http://${req.headers.host||"localhost"}`);
    if(url.pathname==="/health"){send(res,200,{ok:true,service:"EMS School Portal"});}
    else if(url.pathname.startsWith("/api/")) await api(req,res,url); else serveStatic(req,res,url);
  }catch(e){console.error(e);send(res,500,{error:"Server error"});}
});
const PORT=process.env.PORT||3000;
server.listen(PORT,()=>console.log(`EMS Portal running at http://localhost:${PORT}`));
