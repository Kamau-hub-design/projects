const menuToggle = document.querySelector(".menu-toggle");
const navMenu = document.querySelector(".nav-menu");
const yearLabel = document.querySelector("#current-year");
const adminDialog = document.querySelector("#admin-dialog");
const adminStatus = document.querySelector("#admin-status");
const adminLoginForm = document.querySelector("#admin-login-form");
const adminPanel = document.querySelector("#admin-panel");
const projectForm = document.querySelector("#project-form");
const projectGrid = document.querySelector("#project-grid");
const adminProjectList = document.querySelector("#admin-project-list");
const config = window.PORTFOLIO_CONFIG || {};
const hasSupabaseConfig = Boolean(
    config.url &&
    config.publishableKey &&
    config.ownerEmail &&
    !config.url.includes("YOUR_PROJECT_ID") &&
    !config.publishableKey.includes("YOUR_SUPABASE_") &&
    !config.ownerEmail.includes("YOUR_OWNER_EMAIL")
);
const supabaseClient = hasSupabaseConfig && window.supabase
    ? window.supabase.createClient(config.url, config.publishableKey)
    : null;
let projectsById = new Map();

if (yearLabel) {
    yearLabel.textContent = String(new Date().getFullYear());
}

if (menuToggle && navMenu) {
    const closeMenu = () => {
        menuToggle.setAttribute("aria-expanded", "false");
        menuToggle.setAttribute("aria-label", "Open navigation menu");
        navMenu.classList.remove("is-open");
    };

    menuToggle.addEventListener("click", () => {
        const isExpanded = menuToggle.getAttribute("aria-expanded") === "true";
        menuToggle.setAttribute("aria-expanded", String(!isExpanded));
        menuToggle.setAttribute("aria-label", isExpanded ? "Open navigation menu" : "Close navigation menu");
        navMenu.classList.toggle("is-open", !isExpanded);
    });

    navMenu.querySelectorAll("a").forEach((link) => {
        link.addEventListener("click", closeMenu);
    });

    document.addEventListener("keydown", (event) => {
        if (event.key === "Escape" && menuToggle.getAttribute("aria-expanded") === "true") {
            closeMenu();
            menuToggle.focus();
        }
    });

    document.addEventListener("click", (event) => {
        if (!navMenu.contains(event.target) && !menuToggle.contains(event.target)) {
            closeMenu();
        }
    });
}

const revealElements = document.querySelectorAll(".reveal");
let revealObserver;
if ("IntersectionObserver" in window) {
    revealObserver = new IntersectionObserver((entries, observer) => {
        entries.forEach((entry) => {
            if (entry.isIntersecting) {
                entry.target.classList.add("is-visible");
                observer.unobserve(entry.target);
            }
        });
    }, { threshold: 0.12 });

    revealElements.forEach((element) => revealObserver.observe(element));
} else {
    revealElements.forEach((element) => element.classList.add("is-visible"));
}

const setAdminStatus = (message, kind = "") => {
    if (!adminStatus) return;
    adminStatus.textContent = message;
    adminStatus.dataset.kind = kind;
};

const isOwner = (user) =>
    Boolean(user?.email && config.ownerEmail && user.email.toLowerCase() === config.ownerEmail.toLowerCase());

const createElement = (tagName, className, text) => {
    const element = document.createElement(tagName);
    if (className) element.className = className;
    if (text !== undefined) element.textContent = text;
    return element;
};

const setExternalLink = (link, url) => {
    if (!url) return false;
    try {
        const parsedUrl = new URL(url);
        if (parsedUrl.protocol !== "https:" && parsedUrl.protocol !== "http:") return false;
        link.href = parsedUrl.href;
        link.target = "_blank";
        link.rel = "noopener noreferrer";
        return true;
    } catch {
        return false;
    }
};

const renderPublicProjects = (projects) => {
    if (!projectGrid) return;
    projectGrid.replaceChildren();
    if (projects.length === 0) {
        const emptyState = createElement("p", "project-empty", "No projects have been added to the public portfolio yet.");
        projectGrid.append(emptyState);
        return;
    }

    projects.forEach((project) => {
        const article = createElement("article", "project-card project-large reveal");
        const visual = createElement("div", "project-visual campus-visual");
        visual.setAttribute("aria-hidden", "true");
        const mark = createElement("span", "campus-mark");
        const icon = createElement("i", "fa-solid fa-code");
        mark.append(icon);
        visual.append(mark, createElement("span", "campus-orbit campus-orbit-one"), createElement("span", "campus-orbit campus-orbit-two"));

        const info = createElement("div", "project-info");
        const heading = document.createElement("div");
        heading.append(createElement("p", "project-type", project.category || "PROJECT"));
        heading.append(createElement("h3", "", project.title));
        const details = document.createElement("div");
        details.append(createElement("p", "", project.description));

        const tags = Array.isArray(project.technologies) ? project.technologies : [];
        if (tags.length > 0) {
            const tagList = createElement("div", "tag-list project-tags");
            tags.forEach((technology) => tagList.append(createElement("span", "", technology)));
            details.append(tagList);
        }

        if (project.project_url) {
            const link = createElement("a", "project-repo-link", "View project");
            const linkIcon = createElement("i", "fa-solid fa-arrow-up-right-from-square");
            linkIcon.setAttribute("aria-hidden", "true");
            link.append(linkIcon);
            if (setExternalLink(link, project.project_url)) details.append(link);
        }

        info.append(heading, details);
        article.append(visual, info);
        projectGrid.append(article);
        if (revealObserver) {
            revealObserver.observe(article);
        } else {
            article.classList.add("is-visible");
        }
    });
};

const showProjectLoadError = (error) => {
    console.error("Could not load portfolio projects from Supabase:", error);
    if (!projectGrid) return;
    let status = document.querySelector("#project-load-status");
    if (!status) {
        status = createElement("p", "project-load-status");
        status.id = "project-load-status";
        status.setAttribute("role", "status");
        projectGrid.after(status);
    }
    status.textContent = "The live project list could not be loaded. Please try again later.";
};

const fetchProjects = async () => {
    if (!supabaseClient) return [];
    const { data, error } = await supabaseClient
        .from("projects")
        .select("id, title, description, category, technologies, project_url, created_at")
        .order("created_at", { ascending: false });
    if (error) throw error;
    return data || [];
};

const loadPublicProjects = async () => {
    if (!supabaseClient) return;
    try {
        const projects = await fetchProjects();
        renderPublicProjects(projects);
    } catch (error) {
        showProjectLoadError(error);
    }
};

const renderAdminProjects = (projects) => {
    if (!adminProjectList) return;
    projectsById = new Map(projects.map((project) => [project.id, project]));
    adminProjectList.replaceChildren();

    if (projects.length === 0) {
        adminProjectList.append(createElement("p", "admin-empty", "No projects yet. Use the form above to add your first one."));
        return;
    }

    projects.forEach((project) => {
        const item = createElement("div", "admin-project-item");
        const summary = document.createElement("div");
        summary.append(createElement("strong", "", project.title));
        summary.append(createElement("span", "", project.category || "Project"));

        const actions = createElement("div", "admin-project-actions");
        const editButton = createElement("button", "text-button", "Edit");
        editButton.type = "button";
        editButton.dataset.editProject = project.id;
        const deleteButton = createElement("button", "text-button", "Delete");
        deleteButton.type = "button";
        deleteButton.dataset.deleteProject = project.id;
        actions.append(editButton, deleteButton);
        item.append(summary, actions);
        adminProjectList.append(item);
    });
};

const loadAdminProjects = async () => {
    const projects = await fetchProjects();
    renderAdminProjects(projects);
    renderPublicProjects(projects);
};

const showAdminPanel = async (user) => {
    if (!isOwner(user)) {
        if (supabaseClient) await supabaseClient.auth.signOut();
        adminPanel.hidden = true;
        adminLoginForm.hidden = false;
        setAdminStatus("This account is not authorized to manage the portfolio.", "error");
        return;
    }

    adminLoginForm.hidden = true;
    adminPanel.hidden = false;
    document.querySelector("#admin-user-email").textContent = user.email;
    setAdminStatus("");
    try {
        await loadAdminProjects();
    } catch (error) {
        console.error("Could not load projects for portfolio management:", error);
        setAdminStatus("Could not load projects. Check your Supabase table and row-level security setup.", "error");
    }
};

const openAdmin = async () => {
    if (!adminDialog) return;
    if (menuToggle && navMenu) {
        menuToggle.setAttribute("aria-expanded", "false");
        menuToggle.setAttribute("aria-label", "Open navigation menu");
        navMenu.classList.remove("is-open");
    }
    adminDialog.showModal();
    adminLoginForm.hidden = false;
    adminPanel.hidden = true;

    if (!supabaseClient) {
        setAdminStatus("Set the Supabase URL, publishable/anon key, and owner email in supabase-config.js, then run supabase-setup.sql.", "error");
        return;
    }

    setAdminStatus("Checking sign-in…");
    try {
        const { data, error } = await supabaseClient.auth.getSession();
        if (error) throw error;
        if (data.session?.user) {
            await showAdminPanel(data.session.user);
        } else {
            setAdminStatus("Sign in with the owner account configured in Supabase.");
        }
    } catch (error) {
        console.error("Could not check the owner session:", error);
        setAdminStatus("Could not connect to Supabase. Check the project settings and try again.", "error");
    }
};

document.querySelectorAll("[data-open-admin]").forEach((button) => {
    button.addEventListener("click", openAdmin);
});

document.querySelector("[data-close-admin]")?.addEventListener("click", () => adminDialog.close());

adminLoginForm?.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!supabaseClient) {
        setAdminStatus("Supabase is not configured. Update supabase-config.js first.", "error");
        return;
    }

    const formData = new FormData(adminLoginForm);
    setAdminStatus("Signing in…");
    try {
        const { data, error } = await supabaseClient.auth.signInWithPassword({
            email: String(formData.get("email")).trim(),
            password: String(formData.get("password"))
        });
        if (error) throw error;
        if (!isOwner(data.user)) {
            await supabaseClient.auth.signOut();
            throw new Error("This account is not authorized to manage the portfolio.");
        }
        await showAdminPanel(data.user);
    } catch (error) {
        console.error("Owner sign-in failed:", error);
        setAdminStatus(error.message || "Sign-in failed. Check your account and try again.", "error");
    }
});

projectForm?.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!supabaseClient) return;

    const formData = new FormData(projectForm);
    const projectId = String(formData.get("id") || "");
    const urlValue = String(formData.get("project_url") || "").trim();
    const project = {
        title: String(formData.get("title")).trim(),
        category: String(formData.get("category") || "").trim() || "Project",
        description: String(formData.get("description")).trim(),
        technologies: String(formData.get("technologies") || "").split(",").map((item) => item.trim()).filter(Boolean),
        project_url: urlValue || null
    };

    setAdminStatus(projectId ? "Updating project…" : "Saving project…");
    try {
        const query = projectId
            ? supabaseClient.from("projects").update(project).eq("id", projectId)
            : supabaseClient.from("projects").insert(project);
        const { error } = await query;
        if (error) throw error;
        projectForm.reset();
        await loadAdminProjects();
        setAdminStatus("Project saved.", "success");
    } catch (error) {
        console.error("Could not save portfolio project:", error);
        setAdminStatus("Could not save the project. Check your connection and Supabase owner policies.", "error");
    }
});

projectForm?.addEventListener("reset", () => {
    projectForm.elements.id.value = "";
});

adminProjectList?.addEventListener("click", async (event) => {
    const editButton = event.target.closest("[data-edit-project]");
    if (editButton) {
        const project = projectsById.get(editButton.dataset.editProject);
        if (!project) return;
        projectForm.elements.id.value = project.id;
        projectForm.elements.title.value = project.title;
        projectForm.elements.category.value = project.category || "";
        projectForm.elements.description.value = project.description;
        projectForm.elements.technologies.value = (project.technologies || []).join(", ");
        projectForm.elements.project_url.value = project.project_url || "";
        projectForm.elements.title.focus();
        setAdminStatus(`Editing ${project.title}.`, "success");
        return;
    }

    const deleteButton = event.target.closest("[data-delete-project]");
    if (!deleteButton || !window.confirm("Delete this project from the public portfolio?")) return;
    setAdminStatus("Deleting project…");
    try {
        const { error } = await supabaseClient
            .from("projects")
            .delete()
            .eq("id", deleteButton.dataset.deleteProject);
        if (error) throw error;
        await loadAdminProjects();
        setAdminStatus("Project deleted.", "success");
    } catch (error) {
        console.error("Could not delete portfolio project:", error);
        setAdminStatus("Could not delete the project. Check your connection and Supabase owner policies.", "error");
    }
});

document.querySelector("#admin-sign-out")?.addEventListener("click", async () => {
    if (!supabaseClient) return;
    try {
        const { error } = await supabaseClient.auth.signOut();
        if (error) throw error;
        adminPanel.hidden = true;
        adminLoginForm.hidden = false;
        adminLoginForm.reset();
        setAdminStatus("You have signed out.", "success");
    } catch (error) {
        console.error("Owner sign-out failed:", error);
        setAdminStatus("Could not sign out. Please try again.", "error");
    }
});

loadPublicProjects();
